// =======================
// qhash/salthierarchy.go
// =======================

package qhash

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

// GenerateSaltHierarchy builds Master, Stage, Timestamp, Meta salts.
func GenerateSaltHierarchy(numStages, hashSize int) (*HierarchicalSalt, error) {
	if numStages <= 0 || numStages > 10 {
		return nil, fmt.Errorf("invalid number of stages")
	}

	// Scale salt sizes based on hash size
	masterSize := 32 + (hashSize-256)/256*16 // 32-80 bytes
	if masterSize > 80 {
		masterSize = 80
	}

	master := make([]byte, masterSize)
	if _, err := rand.Read(master); err != nil {
		return nil, fmt.Errorf("master salt generation failed: %w", err)
	}

	stageSaltSize := 16 + (hashSize-256)/256*8 // 16-48 bytes
	if stageSaltSize > 48 {
		stageSaltSize = 48
	}

	stageSalts := make([][]byte, numStages)
	for i := 0; i < numStages; i++ {
		seed := append(master, byte(i))
		salt := deriveSaltLR(seed, stageSaltSize)
		if salt == nil {
			return nil, fmt.Errorf("stage %d salt generation failed", i)
		}
		stageSalts[i] = salt
	}

	// Time-based salt (changes hourly to prevent rainbow tables)
	hr := time.Now().Unix() / 3600
	tb := make([]byte, 8)
	binary.BigEndian.PutUint64(tb, uint64(hr))

	timestampSize := 12 + (hashSize-256)/256*4 // 12-28 bytes
	if timestampSize > 28 {
		timestampSize = 28
	}

	ts := deriveSaltLR(tb, timestampSize)
	if ts == nil {
		return nil, fmt.Errorf("timestamp salt generation failed")
	}

	// Meta salt combines all other salts
	metaSeed := make([]byte, 0, len(master)+len(ts)+numStages*stageSaltSize)
	metaSeed = append(metaSeed, master...)
	metaSeed = append(metaSeed, ts...)
	for _, s := range stageSalts {
		metaSeed = append(metaSeed, s...)
	}

	metaSize := 24 + (hashSize-256)/256*8 // 24-56 bytes
	if metaSize > 56 {
		metaSize = 56
	}

	meta := deriveSaltLR(metaSeed, metaSize)
	if meta == nil {
		return nil, fmt.Errorf("meta salt generation failed")
	}

	return &HierarchicalSalt{
		MasterSalt:    master,
		StageSalts:    stageSalts,
		TimestampSalt: ts,
		MetaSalt:      meta,
		HashSize:      hashSize,
	}, nil
}
