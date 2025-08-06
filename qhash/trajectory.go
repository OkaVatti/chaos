package qhash

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

// seedBig derives three big.Float values in [-20,20) from data||salt.
func seedBig(data, salt []byte) (*big.Float, *big.Float, *big.Float, error) {
	if len(data) == 0 || len(salt) == 0 {
		return nil, nil, nil, fmt.Errorf("empty input data")
	}

	combined := make([]byte, 0, len(data)+len(salt))
	combined = append(combined, data...)
	combined = append(combined, salt...)

	h := sha256.Sum256(combined)
	denom := new(big.Float).SetInt(new(big.Int).Lsh(big.NewInt(1), 64))
	denom.SetPrec(128)

	mk := func(off int) (*big.Float, error) {
		if off+8 > len(h) {
			return nil, fmt.Errorf("insufficient hash bytes")
		}
		u := binary.BigEndian.Uint64(h[off : off+8])
		f := new(big.Float).SetUint64(u).SetPrec(128) // [0,2^64)
		f.Quo(f, denom)                               // [0,1)
		f.Mul(f, big.NewFloat(40.0))                  // [0,40)
		return f.Sub(f, big.NewFloat(20.0)), nil      // [-20,20)
	}

	x, err := mk(0)
	if err != nil {
		return nil, nil, nil, err
	}
	y, err := mk(8)
	if err != nil {
		return nil, nil, nil, err
	}
	z, err := mk(16)
	if err != nil {
		return nil, nil, nil, err
	}

	return x, y, z, nil
}

// discretize extracts one byte from f by taking its fractional part.
func discretize(f *big.Float) (byte, error) {
	if f == nil {
		return 0, fmt.Errorf("nil big.Float")
	}

	// Copy f to avoid mutating caller's value
	c := new(big.Float).Copy(f).SetPrec(128)

	// Get integer part
	intPart, _ := c.Int(nil) // truncates toward zero

	// frac = c - intPart
	frac := new(big.Float).Sub(c, new(big.Float).SetInt(intPart))

	// Handle negative fractions
	if frac.Sign() < 0 {
		frac.Add(frac, big.NewFloat(1.0))
	}

	// Scale up fraction
	frac.Mul(frac, big.NewFloat(256.0))

	// Extract integer from scaled fraction
	fracInt, _ := frac.Int(nil)
	return byte(fracInt.Uint64() & 0xFF), nil
}

// TrajectoryToHashBig evolves the Lorenz system in high precision with size-aware parameters.
func TrajectoryToHashBig(
	x0, y0, z0 *big.Float,
	sigma, rho, beta, dt *big.Float,
	iterations, discard, outSize int,
) ([]byte, error) {
	if x0 == nil || y0 == nil || z0 == nil || sigma == nil || rho == nil || beta == nil || dt == nil {
		return nil, fmt.Errorf("nil parameters")
	}

	if iterations < MinIterations || iterations > MaxIterations {
		return nil, fmt.Errorf("iterations out of safe range: %d", iterations)
	}

	if outSize <= 0 || outSize > 128 { // Max 1024 bits / 8 = 128 bytes
		return nil, fmt.Errorf("invalid output size: %d", outSize)
	}

	// Enhanced parameter validation for stability
	if s, _ := sigma.Float64(); s <= 0 || s > 100 {
		return nil, fmt.Errorf("sigma parameter out of range: %f", s)
	}
	if r, _ := rho.Float64(); r <= 0 || r > 100 {
		return nil, fmt.Errorf("rho parameter out of range: %f", r)
	}
	if b, _ := beta.Float64(); b <= 0 || b > 100 {
		return nil, fmt.Errorf("beta parameter out of range: %f", b)
	}
	if d, _ := dt.Float64(); d <= 0 || d > 0.1 {
		return nil, fmt.Errorf("dt parameter out of range: %f", d)
	}

	// Initialize with copies to avoid mutation
	x := new(big.Float).Copy(x0).SetPrec(128)
	y := new(big.Float).Copy(y0).SetPrec(128)
	z := new(big.Float).Copy(z0).SetPrec(128)

	// Enhanced warm-up period to skip initial transients
	for i := 0; i < discard; i++ {
		if err := lorenzStep(x, y, z, sigma, rho, beta, dt); err != nil {
			return nil, fmt.Errorf("warm-up step %d failed: %w", i, err)
		}
	}

	// Generate stream with size-aware extraction strategy
	streamMultiplier := int(math.Ceil(float64(outSize) / 32.0)) // Ensure enough entropy
	if streamMultiplier < 1 {
		streamMultiplier = 1
	}

	stream := make([]byte, 0, iterations*3*streamMultiplier)

	for i := 0; i < iterations; i++ {
		if err := lorenzStep(x, y, z, sigma, rho, beta, dt); err != nil {
			return nil, fmt.Errorf("iteration %d failed: %w", i, err)
		}

		// Extract bytes from coordinates with enhanced entropy extraction
		bx, err := discretize(x)
		if err != nil {
			return nil, fmt.Errorf("x discretization failed: %w", err)
		}
		by, err := discretize(y)
		if err != nil {
			return nil, fmt.Errorf("y discretization failed: %w", err)
		}
		bz, err := discretize(z)
		if err != nil {
			return nil, fmt.Errorf("z discretization failed: %w", err)
		}

		// For larger output sizes, extract more entropy per iteration
		stream = append(stream, bx, by, bz)

		// Additional entropy extraction for larger hash sizes
		if outSize >= 48 { // 384+ bits
			// Extract additional bytes from higher-order bits
			bx2, _ := discretizeWithShift(x, 8)
			by2, _ := discretizeWithShift(y, 8)
			bz2, _ := discretizeWithShift(z, 8)
			stream = append(stream, bx2, by2, bz2)
		}

		if outSize >= 64 { // 512+ bits
			// Extract even more entropy
			bx3, _ := discretizeWithShift(x, 16)
			by3, _ := discretizeWithShift(y, 16)
			bz3, _ := discretizeWithShift(z, 16)
			stream = append(stream, bx3, by3, bz3)
		}

		if outSize >= 128 { // 1024 bits
			// Maximum entropy extraction
			bx4, _ := discretizeWithShift(x, 24)
			by4, _ := discretizeWithShift(y, 24)
			bz4, _ := discretizeWithShift(z, 24)
			stream = append(stream, bx4, by4, bz4)
		}
	}

	if len(stream) == 0 {
		return nil, fmt.Errorf("empty stream generated")
	}

	// Enhanced XOR-fold with multiple mixing rounds for better avalanche effect
	hash := make([]byte, outSize)

	// Round 1: Basic XOR folding
	for i := range hash {
		hash[i] = stream[i%len(stream)] ^ stream[(i*7)%len(stream)]
	}

	// Round 2: Advanced mixing with prime offsets
	for i := range hash {
		hash[i] ^= stream[(i*11)%len(stream)] ^ stream[(i*13)%len(stream)]
	}

	// Round 3: Size-dependent mixing for larger hashes
	if outSize >= 48 {
		for i := range hash {
			hash[i] ^= stream[(i*17)%len(stream)] ^ stream[(i*19)%len(stream)]
		}
	}

	if outSize >= 64 {
		for i := range hash {
			hash[i] ^= stream[(i*23)%len(stream)] ^ stream[(i*29)%len(stream)]
		}
	}

	if outSize >= 128 {
		for i := range hash {
			hash[i] ^= stream[(i*31)%len(stream)] ^ stream[(i*37)%len(stream)]
		}
	}

	return hash, nil
}

// discretizeWithShift extracts a byte from f with a bit shift for additional entropy
func discretizeWithShift(f *big.Float, shift int) (byte, error) {
	if f == nil {
		return 0, fmt.Errorf("nil big.Float")
	}

	// Copy and apply shift
	c := new(big.Float).Copy(f).SetPrec(128)
	shiftFactor := new(big.Float).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(shift)))
	c.Mul(c, shiftFactor)

	// Get integer part
	intPart, _ := c.Int(nil)

	// Extract fractional part
	frac := new(big.Float).Sub(c, new(big.Float).SetInt(intPart))

	// Handle negative fractions
	if frac.Sign() < 0 {
		frac.Add(frac, big.NewFloat(1.0))
	}

	// Scale and extract byte
	frac.Mul(frac, big.NewFloat(256.0))
	fracInt, _ := frac.Int(nil)
	return byte(fracInt.Uint64() & 0xFF), nil
}

// lorenzStep performs one step of Lorenz system evolution with enhanced stability checking
func lorenzStep(x, y, z, sigma, rho, beta, dt *big.Float) error {
	// Compute derivatives
	dx := new(big.Float).Mul(sigma, new(big.Float).Sub(y, x))
	dy := new(big.Float).Sub(
		new(big.Float).Mul(x, new(big.Float).Sub(rho, z)),
		y,
	)
	dz := new(big.Float).Sub(
		new(big.Float).Mul(x, y),
		new(big.Float).Mul(beta, z),
	)

	// Update coordinates
	x.Add(x, new(big.Float).Mul(dx, dt))
	y.Add(y, new(big.Float).Mul(dy, dt))
	z.Add(z, new(big.Float).Mul(dz, dt))

	// Enhanced overflow/underflow checking
	if xf, _ := x.Float64(); math.IsInf(xf, 0) || math.IsNaN(xf) || math.Abs(xf) > 1e10 {
		return fmt.Errorf("x coordinate overflow: %f", xf)
	}
	if yf, _ := y.Float64(); math.IsInf(yf, 0) || math.IsNaN(yf) || math.Abs(yf) > 1e10 {
		return fmt.Errorf("y coordinate overflow: %f", yf)
	}
	if zf, _ := z.Float64(); math.IsInf(zf, 0) || math.IsNaN(zf) || math.Abs(zf) > 1e10 {
		return fmt.Errorf("z coordinate overflow: %f", zf)
	}

	return nil
}
