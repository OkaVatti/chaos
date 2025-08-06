// =======================
// qhash/hasher.go
// =======================

package qhash

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"runtime"
	"time"
)

func NewHardenedLorenzHasher(hashSize int) (*HardenedLorenzHasher, error) {
	size := HashSize(hashSize)
	if size != Size256 && size != Size384 && size != Size512 && size != Size1024 {
		return nil, fmt.Errorf("unsupported hash size: %d. Supported: 256, 384, 512, 1024", hashSize)
	}

	f := func(v float64) *big.Float { return big.NewFloat(v).SetPrec(128) }

	// Define stages for each hash size
	stageConfigs := map[HashSize][]LorenzStage{
		Size256: {
			{f(10), f(28), f(8.0 / 3.0), f(0.01), 2000, 1, "Classic-256"},
			{f(16), f(45.6), f(4), f(0.008), 3000, 2, "Energetic-256"},
		},
		Size384: {
			{f(10), f(28), f(8.0 / 3.0), f(0.01), 2000, 1, "Classic-384"},
			{f(16), f(45.6), f(4), f(0.008), 3000, 2, "Energetic-384"},
			{f(12.5), f(35.2), f(2.5), f(0.012), 2500, 3, "Wide-384"},
		},
		Size512: {
			{f(10), f(28), f(8.0 / 3.0), f(0.01), 2000, 1, "Classic-512"},
			{f(16), f(45.6), f(4), f(0.008), 3000, 2, "Energetic-512"},
			{f(12.5), f(35.2), f(2.5), f(0.012), 2500, 3, "Wide-512"},
			{f(8.5), f(24.8), f(6.2), f(0.015), 1800, 4, "Compact-512"},
		},
		Size1024: {
			{f(10), f(28), f(8.0 / 3.0), f(0.01), 2000, 1, "Classic-1024"},
			{f(16), f(45.6), f(4), f(0.008), 3000, 2, "Energetic-1024"},
			{f(12.5), f(35.2), f(2.5), f(0.012), 2500, 3, "Wide-1024"},
			{f(8.5), f(24.8), f(6.2), f(0.015), 1800, 4, "Compact-1024"},
			{f(14.2), f(32.1), f(3.8), f(0.009), 3200, 5, "Extended-1-1024"},
			{f(11.7), f(41.3), f(5.1), f(0.011), 2800, 6, "Extended-2-1024"},
			{f(9.3), f(26.7), f(7.4), f(0.013), 2200, 7, "Extended-3-1024"},
			{f(13.8), f(38.9), f(2.9), f(0.007), 3500, 8, "Extended-4-1024"},
		},
	}

	stages := stageConfigs[size]

	// Validate stage parameters
	for i, stage := range stages {
		if stage.Iterations < MinIterations || stage.Iterations > MaxIterations {
			return nil, fmt.Errorf("stage %d iterations out of safe range", i)
		}

		// Ensure Lorenz parameters are reasonable
		if sigma, _ := stage.Sigma.Float64(); sigma <= 0 || sigma > 100 {
			return nil, fmt.Errorf("stage %d sigma parameter invalid", i)
		}
		if rho, _ := stage.Rho.Float64(); rho <= 0 || rho > 100 {
			return nil, fmt.Errorf("stage %d rho parameter invalid", i)
		}
		if beta, _ := stage.Beta.Float64(); beta <= 0 || beta > 100 {
			return nil, fmt.Errorf("stage %d beta parameter invalid", i)
		}
		if dt, _ := stage.Dt.Float64(); dt <= 0 || dt > 0.1 {
			return nil, fmt.Errorf("stage %d dt parameter invalid", i)
		}
	}

	stageMap := make(map[HashSize][]LorenzStage)
	stageMap[size] = stages

	return &HardenedLorenzHasher{
		stages:         stageMap,
		memoryHardness: DefaultMemoryHardness,
		minComputeTime: MinComputeTime,
		hashSize:       size,
	}, nil
}

func (h *HardenedLorenzHasher) GetHashSize() int {
	return int(h.hashSize)
}

func (h *HardenedLorenzHasher) HashWithHardening(data []byte) (*HardenedSaltedHash, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data not allowed")
	}

	salt, err := h.generateSalt()
	if err != nil {
		return nil, fmt.Errorf("salt generation failed: %w", err)
	}

	params := deriveAdaptiveParameters(data, salt.MasterSalt)
	return h.compute(data, salt, params)
}

func (h *HardenedLorenzHasher) compute(
	data []byte,
	salt *HierarchicalSalt,
	params map[string]interface{},
) (*HardenedSaltedHash, error) {
	start := time.Now()
	var checkpoints []TrajectoryCheckpoint
	buf := make([]byte, len(data))
	copy(buf, data) // Defensive copy

	stages := h.stages[h.hashSize]
	outputSize := int(h.hashSize) / 8 // Convert bits to bytes

	for idx, st := range stages {
		if idx >= len(salt.StageSalts) {
			return nil, fmt.Errorf("insufficient stage salts")
		}

		// Combine with stage salt
		buf = append(buf, salt.StageSalts[idx]...)

		// Generate initial conditions
		x0, y0, z0, err := seedBig(buf, salt.MasterSalt)
		if err != nil {
			return nil, fmt.Errorf("seed generation failed: %w", err)
		}

		// Run Lorenz trajectory with size-appropriate parameters
		iterations := st.Iterations
		discard := 1000 + int(h.hashSize)/4 // More discard for larger sizes

		bytesOut, err := TrajectoryToHashBig(
			x0, y0, z0,
			st.Sigma, st.Rho, st.Beta, st.Dt,
			iterations, discard, outputSize,
		)
		if err != nil {
			return nil, fmt.Errorf("trajectory computation failed: %w", err)
		}

		// Create checkpoint with appropriate hash function
		var sum []byte
		switch h.hashSize {
		case Size256:
			h256 := sha256.Sum256(bytesOut)
			sum = h256[:]
		case Size384:
			h384 := sha512.Sum384(bytesOut)
			sum = h384[:]
		case Size512:
			h512 := sha512.Sum512(bytesOut)
			sum = h512[:]
		case Size1024:
			// For 1024, use double SHA-512
			h1 := sha512.Sum512(bytesOut)
			h2 := sha512.Sum512(h1[:])
			sum = append(h1[:], h2[:]...)
		}

		checkpoints = append(checkpoints, TrajectoryCheckpoint{
			Stage:     idx,
			Iteration: st.Iterations,
			Hash:      base64.StdEncoding.EncodeToString(sum),
			Size:      int(h.hashSize),
		})

		buf = bytesOut
	}

	// Final quantum-resistant mixing
	finalHash, err := quantumFinalize(buf, salt, h.hashSize)
	if err != nil {
		return nil, fmt.Errorf("quantum finalization failed: %w", err)
	}

	// Enforce minimum computation time to prevent timing attacks
	if dt := time.Since(start); dt < h.minComputeTime {
		time.Sleep(h.minComputeTime - dt)
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &HardenedSaltedHash{
		Hash:        finalHash,
		Salt:        salt,
		Checkpoints: checkpoints,
		ComputeTime: time.Since(start).Nanoseconds(),
		MemoryUsed:  int(m.Alloc / 1024),
		Parameters:  params,
		Algorithm:   fmt.Sprintf("QHASH-%d", int(h.hashSize)),
		Version:     "2.0",
		HashSize:    int(h.hashSize),
	}, nil
}

func (h *HardenedLorenzHasher) Hash(data []byte) ([]byte, error) {
	result, err := h.HashWithHardening(data)
	if err != nil {
		return nil, err
	}
	return result.Hash, nil
}

func (h *HardenedLorenzHasher) VerifyHardenedHash(
	data []byte, stored *HardenedSaltedHash,
) (bool, error) {
	if stored == nil || stored.Salt == nil {
		return false, fmt.Errorf("invalid stored hash")
	}

	// Verify hash size compatibility
	if stored.HashSize != int(h.hashSize) {
		return false, fmt.Errorf("hash size mismatch: expected %d, got %d",
			int(h.hashSize), stored.HashSize)
	}

	// Recompute hash using stored salt
	params := deriveAdaptiveParameters(data, stored.Salt.MasterSalt)
	recomputed, err := h.compute(data, stored.Salt, params)
	if err != nil {
		return false, fmt.Errorf("recomputation failed: %w", err)
	}

	// Compare hashes
	if !bytes.Equal(recomputed.Hash, stored.Hash) {
		return false, nil
	}

	// Verify checkpoints
	if len(recomputed.Checkpoints) != len(stored.Checkpoints) {
		return false, nil
	}

	for i, cp := range recomputed.Checkpoints {
		if cp.Hash != stored.Checkpoints[i].Hash {
			return false, nil
		}
	}

	return true, nil
}

func (h *HardenedLorenzHasher) generateSalt() (*HierarchicalSalt, error) {
	return GenerateSaltHierarchy(len(h.stages[h.hashSize]), int(h.hashSize))
}

func (h *HardenedLorenzHasher) ExposeStages() []LorenzStage {
	stages := h.stages[h.hashSize]
	result := make([]LorenzStage, len(stages))
	copy(result, stages)
	return result
}
