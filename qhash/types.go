// =======================
// qhash/types.go
// =======================

package qhash

import (
	"math/big"
	"time"
)

const (
	MinComputeTime        = 100 * time.Millisecond
	DefaultMemoryHardness = 512
	MaxIterations         = 100000 // Prevent DoS
	MinIterations         = 1000
)

// HashSize represents supported hash output sizes
type HashSize int

const (
	Size256  HashSize = 256
	Size384  HashSize = 384
	Size512  HashSize = 512
	Size1024 HashSize = 1024
)

// LorenzStage represents one stage of multi-stage Lorenz computation
type LorenzStage struct {
	Sigma, Rho, Beta, Dt *big.Float
	Iterations           int
	StageID              int    `json:"stage_id"`
	Description          string `json:"description"`
}

type HierarchicalSalt struct {
	MasterSalt    []byte   `json:"master_salt"`
	StageSalts    [][]byte `json:"stage_salts"`
	TimestampSalt []byte   `json:"timestamp_salt"`
	MetaSalt      []byte   `json:"meta_salt"`
	HashSize      int      `json:"hash_size"`
}

type TrajectoryCheckpoint struct {
	Stage     int    `json:"stage"`
	Iteration int    `json:"iteration"`
	Hash      string `json:"hash"`
	Size      int    `json:"size"`
}

type HardenedSaltedHash struct {
	Hash        []byte                 `json:"hash"`
	Salt        *HierarchicalSalt      `json:"salt"`
	Checkpoints []TrajectoryCheckpoint `json:"checkpoints"`
	ComputeTime int64                  `json:"compute_time_ns"`
	MemoryUsed  int                    `json:"memory_used_kb"`
	Parameters  map[string]interface{} `json:"parameters"`
	Algorithm   string                 `json:"algorithm"`
	Version     string                 `json:"version"`
	HashSize    int                    `json:"hash_size"`
}

type HardenedLorenzHasher struct {
	stages         map[HashSize][]LorenzStage
	memoryHardness int
	minComputeTime time.Duration
	hashSize       HashSize
}
