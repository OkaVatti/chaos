// =======================
// qhash/point3d.go
// =======================

package qhash

import "math"

// Point3D holds a 3D coordinate.
type Point3D struct{ X, Y, Z float64 }

// Rotate rotates around X, Y, Z axes using proper rotation matrices.
func (p Point3D) Rotate(ax, ay, az float64) Point3D {
	cosX, sinX := math.Cos(ax), math.Sin(ax)
	cosY, sinY := math.Cos(ay), math.Sin(ay)
	cosZ, sinZ := math.Cos(az), math.Sin(az)

	// X-axis rotation
	y1 := p.Y*cosX - p.Z*sinX
	z1 := p.Y*sinX + p.Z*cosX
	p.Y, p.Z = y1, z1

	// Y-axis rotation
	x1 := p.X*cosY + p.Z*sinY
	z2 := -p.X*sinY + p.Z*cosY
	p.X, p.Z = x1, z2

	// Z-axis rotation
	x2 := p.X*cosZ - p.Y*sinZ
	y2 := p.X*sinZ + p.Y*cosZ
	p.X, p.Y = x2, y2

	return p
}
