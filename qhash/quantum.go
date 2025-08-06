package qhash

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// lorenzMix: XOR with SHA-derived bytes
func lorenzMix(data, salt []byte) ([]byte, error) {
	if len(data) == 0 || len(salt) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	out := make([]byte, len(data))
	combined := make([]byte, 0, len(data)+len(salt))
	combined = append(combined, data...)
	combined = append(combined, salt...)

	h := sha256.Sum256(combined)
	for i := range out {
		out[i] = data[i] ^ h[i%len(h)]
	}
	return out, nil
}

// hyperchaosMix: 4D chaotic mixing
func hyperchaosMix(data, salt []byte) ([]byte, error) {
	if len(data) == 0 || len(salt) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	out := make([]byte, len(data))
	key := sha256.Sum256(salt)

	for i := range out {
		val := data[i]
		val ^= key[(i*7)%len(key)]
		val ^= key[(i*13)%len(key)]
		val = byte((int(val) + int(key[(i*17)%len(key)])) % 256)
		out[i] = val
	}
	return out, nil
}

// latticeMix: Lattice-based mixing inspired by Learning With Errors
func latticeMix(data, salt []byte) ([]byte, error) {
	if len(data) == 0 || len(salt) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	out := make([]byte, len(data))
	h := sha256.Sum256(salt)

	for i := range out {
		sum := 0
		for j := 0; j < len(data); j++ {
			sum += int(data[j]) * int(h[(i+j)%len(h)])
		}
		noise := int(h[(i*3)%len(h)])
		out[i] = byte((sum + noise) % 256)
	}
	return out, nil
}

// quantumFinalize: Multi-round mixing for quantum resistance
func quantumFinalize(data []byte, salt *HierarchicalSalt, hashSize HashSize) ([]byte, error) {
	if len(data) == 0 || salt == nil {
		return nil, fmt.Errorf("invalid input")
	}

	// Round 1: Basic hashing with size-appropriate hash function
	combined := make([]byte, 0, len(data)+len(salt.MasterSalt))
	combined = append(combined, data...)
	combined = append(combined, salt.MasterSalt...)

	var r1 []byte
	switch hashSize {
	case Size256:
		h := sha256.Sum256(combined)
		r1 = h[:]
	case Size384:
		h := sha512.Sum384(combined)
		r1 = h[:]
	case Size512:
		h := sha512.Sum512(combined)
		r1 = h[:]
	case Size1024:
		h1 := sha512.Sum512(combined)
		h2 := sha512.Sum512(h1[:])
		r1 = append(h1[:], h2[:]...)
	}

	// Round 2: Lorenz mixing
	r2, err := lorenzMix(r1, salt.MetaSalt)
	if err != nil {
		return nil, fmt.Errorf("lorenz mix failed: %w", err)
	}

	// Round 3: Hyperchaos mixing
	r3, err := hyperchaosMix(r2, salt.TimestampSalt)
	if err != nil {
		return nil, fmt.Errorf("hyperchaos mix failed: %w", err)
	}

	// Round 4: Lattice mixing
	r4, err := latticeMix(r3, salt.MasterSalt)
	if err != nil {
		return nil, fmt.Errorf("lattice mix failed: %w", err)
	}

	// Final round: Size-appropriate final hash
	outputSize := int(hashSize) / 8
	var final []byte

	switch hashSize {
	case Size256:
		h := sha256.Sum256(r4)
		final = h[:]
	case Size384:
		h := sha512.Sum384(r4)
		final = h[:]
	case Size512:
		h := sha512.Sum512(r4)
		final = h[:]
	case Size1024:
		h1 := sha512.Sum512(r4)
		h2 := sha512.Sum512(h1[:])
		final = append(h1[:], h2[:]...)
	}

	// Ensure exact output size
	if len(final) > outputSize {
		final = final[:outputSize]
	} else if len(final) < outputSize {
		// Expand if needed
		for len(final) < outputSize {
			h := sha256.Sum256(final)
			final = append(final, h[:]...)
		}
		final = final[:outputSize]
	}

	return final, nil
}
