// =======================
// qhash/adaptive.go
// =======================

package qhash

import (
	"crypto/sha256"
	"encoding/base64"
)

// deriveAdaptiveParameters creates deterministic parameters from input.
func deriveAdaptiveParameters(data, salt []byte) map[string]interface{} {
	combined := make([]byte, 0, len(data)+len(salt))
	combined = append(combined, data...)
	combined = append(combined, salt...)

	h := sha256.Sum256(combined)
	params := make(map[string]interface{})

	// Derive parameters within safe ranges
	params["iteration_multiplier"] = 0.8 + (float64(h[0])/255.0)*0.4 // [0.8, 1.2]
	params["dt_scale"] = 0.9 + (float64(h[1])/255.0)*0.2             // [0.9, 1.1]
	params["memory_multiplier"] = 1.0 + (float64(h[2])/255.0)*1.0    // [1.0, 2.0]
	params["sigma_perturbation"] = (float64(h[3])/255.0 - 0.5) * 1.0 // [-0.5, 0.5]
	params["rho_perturbation"] = (float64(h[4])/255.0 - 0.5) * 2.0   // [-1.0, 1.0]
	params["beta_perturbation"] = (float64(h[5])/255.0 - 0.5) * 0.5  // [-0.25, 0.25]
	params["quantum_resistance_level"] = int(h[6])%4 + 1             // [1, 4]

	return params
}

// deriveSaltLR produces a salt of the given size via chained SHA256.
func deriveSaltLR(seed []byte, size int) []byte {
	if size <= 0 || size > 1024 {
		return nil
	}

	salt := make([]byte, size)
	buf := make([]byte, len(seed))
	copy(buf, seed)

	for i := 0; i < size; i++ {
		h := sha256.Sum256(buf)
		salt[i] = h[0]
		buf = h[:]
	}
	return salt
}

func makeCheckpoint(stage, iteration int, data []byte) TrajectoryCheckpoint {
	sum := sha256.Sum256(data)
	return TrajectoryCheckpoint{
		Stage:     stage,
		Iteration: iteration,
		Hash:      base64.StdEncoding.EncodeToString(sum[:]),
	}
}
