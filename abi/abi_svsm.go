// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package abi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"

	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/uuid"
)

const (
	GUID_HEADER_ENTRY_SIZE = 24
)

// GUID as specified in Table 12 of the SVSM specification
var SERVICES_MANIFEST_GUID = uuid.MustParse("63849ebb-3d92-4670-a1ff-58f9c94b87bb")

// vTPM service attestation GUID found in Section 8.3.1 of the SVSM specification
var SVSM_ATTEST_VTPM_GUID = uuid.MustParse("c476f1eb-0123-45a5-9641-b4e7dde5bfe3")

// ServicesManifest represents the services manifest table, as defined in Section 7.1,
// table 12 of the Secure VM Service Module for SEV-SNP Guests specification:
// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/58019.pdf
type ServicesManifest struct {
	Entries []ServiceEntry
}

type ServiceEntry struct {
	GUID uuid.UUID
	Data []byte
}

func (t *ServicesManifest) headerSize() uint {
	return uint((1 + len(t.Entries)) * GUID_HEADER_ENTRY_SIZE)
}

// Returns the number of bytes taken up by the wire ABI representation
func (t *ServicesManifest) len() uint {
	var size uint = t.headerSize()
	for _, entry := range t.Entries {
		size += uint(len(entry.Data))
	}
	return size
}

func (t *ServicesManifest) GetEntry(guid uuid.UUID) (ServiceEntry, error) {
	for _, entry := range t.Entries {
		if entry.GUID == guid {
			return entry, nil
		}
	}
	return ServiceEntry{}, fmt.Errorf("entry not found for GUID %s", guid.String())
}

func (t *ServicesManifest) Marshal() ([]byte, error) {
	var result bytes.Buffer

	manifestGuidLittleEndian := UUIDToLittleEndian(SERVICES_MANIFEST_GUID)
	// Write the main header: SERVICES_MANIFEST_GUID | length of table in bytes | number of entries in table
	err := binary.Write(&result, binary.LittleEndian, manifestGuidLittleEndian)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Services Manifest: %w", err)
	}

	tableLen := uint32(t.len())
	err = binary.Write(&result, binary.LittleEndian, tableLen)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Services Manifest: %w", err)
	}

	numEntries := uint32(len(t.Entries))
	err = binary.Write(&result, binary.LittleEndian, numEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Services Manifest: %w", err)
	}

	// Write header for each entry in the table, which contains:
	// service GUID | offset of data from start of table | length of data
	var cursor uint32 = uint32(t.headerSize())
	for _, entry := range t.Entries {
		littleEndianGuid := UUIDToLittleEndian(entry.GUID)
		err = binary.Write(&result, binary.LittleEndian, littleEndianGuid)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Services Manifest: %w", err)
		}

		err = binary.Write(&result, binary.LittleEndian, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Services Manifest: %w", err)
		}

		entryLen := uint32(len(entry.Data))
		err = binary.Write(&result, binary.LittleEndian, entryLen)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Services Manifest: %w", err)
		}

		cursor += entryLen
	}

	// Write the data.
	for _, entry := range t.Entries {
		bytesWritten, err := result.Write(entry.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Services Manifest: %w", err)
		}
		if bytesWritten != len(entry.Data) {
			return nil, errors.New("failed to marshal Services Manifest: unexpected number of bytes written")
		}
	}

	return result.Bytes(), nil

}

func (t *ServicesManifest) Unmarshal(data []byte) error {
	buf := bytes.NewBuffer(data)
	totalBytesRead := 0

	var expectedGuidBuf bytes.Buffer
	err := binary.Write(&expectedGuidBuf, binary.LittleEndian, SERVICES_MANIFEST_GUID)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
	}
	var expectedGuid uuid.UUID
	expectedGuidBytes := UUIDToLittleEndian(SERVICES_MANIFEST_GUID)
	copy(expectedGuid[:], expectedGuidBytes)

	// Read the main header: SERVICES_MANIFEST_GUID | length of table in bytes | number of entries in table
	var guid uuid.UUID
	err = binary.Read(buf, binary.LittleEndian, &guid)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
	}
	if guid != expectedGuid {
		return fmt.Errorf("failed to unmarshal Services Manifest: unexpected GUID: %s", guid.String())
	}
	totalBytesRead += int(reflect.TypeOf(guid).Size())

	var tableLen uint32
	err = binary.Read(buf, binary.LittleEndian, &tableLen)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
	}
	if tableLen != uint32(len(data)) {
		return fmt.Errorf("failed to unmarshal Services Manifest: unexpected table length")
	}
	totalBytesRead += int(reflect.TypeOf(tableLen).Size())

	var numEntries uint32
	err = binary.Read(buf, binary.LittleEndian, &numEntries)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
	}
	totalBytesRead += int(reflect.TypeOf(numEntries).Size())

	// Read header for each entry in the table, which contains:
	// service GUID | offset of data from start of table | length of data
	for i := uint32(0); i < numEntries; i++ {
		var entry ServiceEntry
		var littleEndianGuid uuid.UUID
		err := binary.Read(buf, binary.LittleEndian, &littleEndianGuid)
		if err != nil {
			return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
		}
		totalBytesRead += int(reflect.TypeOf(entry.GUID).Size())

		entry.GUID, err = LittleEndianToUUID(littleEndianGuid[:])
		if err != nil {
			return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
		}

		var offset uint32
		err = binary.Read(buf, binary.LittleEndian, &offset)
		if err != nil {
			return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
		}
		totalBytesRead += int(reflect.TypeOf(offset).Size())

		var dataLen uint32
		err = binary.Read(buf, binary.LittleEndian, &dataLen)
		if err != nil {
			return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
		}
		totalBytesRead += int(reflect.TypeOf(dataLen).Size())

		entry.Data = make([]byte, dataLen)
		t.Entries = append(t.Entries, entry)
	}

	// Read the data for each service entry
	for _, entry := range t.Entries {
		bytesRead, err := buf.Read(entry.Data)
		if err != nil {
			return fmt.Errorf("failed to unmarshal Services Manifest: %w", err)
		}
		if bytesRead != len(entry.Data) {
			return fmt.Errorf("failed to unmarshal Services Manifest: unexpected number of bytes read")
		}
		totalBytesRead += bytesRead
	}

	if totalBytesRead != len(data) {
		return fmt.Errorf("failed to unmarshal Services Manifest: unexpected number of bytes read")
	}

	return nil
}

func ServicesManifestFromProto(servicesManifest *pb.ServicesManifest) (*ServicesManifest, error) {
	result := &ServicesManifest{}
	for _, entry := range servicesManifest.Services {
		guid, err := uuid.Parse(entry.Guid)
		if err != nil {
			return nil, fmt.Errorf("failed to parse GUID: %w", err)
		}
		result.Entries = append(result.Entries, ServiceEntry{GUID: guid, Data: entry.Data})
	}
	return result, nil
}

func (t *ServicesManifest) Proto() *pb.ServicesManifest {
	result := &pb.ServicesManifest{}
	for _, entry := range t.Entries {
		result.Services = append(result.Services, &pb.ServicesManifestEntry{Guid: entry.GUID.String(), Data: entry.Data})
	}
	return result
}

// Helper functions for converting UUIDs to and from little-endian format.
func UUIDToLittleEndian(u uuid.UUID) []byte {
	result := make([]byte, 16)

	// Copy the original UUID bytes
	copy(result, u[:])

	// Reverse Time Low (bytes 0-3)
	for i := 0; i < 2; i++ {
		result[i], result[3-i] = result[3-i], result[i]
	}

	// Reverse Time Mid (bytes 4-5)
	result[4], result[5] = result[5], result[4]

	// Reverse Time High and Version (bytes 6-7)
	result[6], result[7] = result[7], result[6]

	// Clock Sequence and Node (bytes 8-15) remain unchanged

	return result
}

func LittleEndianToUUID(data []byte) (uuid.UUID, error) {
	if len(data) != 16 {
		return uuid.UUID{}, fmt.Errorf("invalid data length: expected 16 bytes, got %d", len(data))
	}

	result := make([]byte, 16)
	copy(result, data)

	// Reverse Time Low (bytes 0-3) back to big-endian
	for i := 0; i < 2; i++ {
		result[i], result[3-i] = result[3-i], result[i]
	}

	// Reverse Time Mid (bytes 4-5) back to big-endian
	result[4], result[5] = result[5], result[4]

	// Reverse Time High and Version (bytes 6-7) back to big-endian
	result[6], result[7] = result[7], result[6]

	// Clock Sequence and Node (bytes 8-15) remain unchanged

	var u uuid.UUID
	copy(u[:], result)
	return u, nil
}
