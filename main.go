// main.go
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"time"

	"chaos/v2/qhash"

	"github.com/gdamore/tcell/v2"
)

func main() {
	graphics := flag.Bool("graphics", false, "Enable graphics visualization")
	genH := flag.Bool("genhardened", false, "Generate hardened hash")
	gen := flag.Bool("genhash", false, "Generate simple hash")
	in := flag.String("input", "", "Input data to hash")
	file := flag.String("file", "", "File path to hash")
	vr := flag.String("verify", "", "Data to verify against hash")
	verifyFile := flag.String("verifyfile", "", "File to verify against hash")
	hjson := flag.String("hardenedhash", "", "Hardened hash JSON (base64 or raw)")
	hash64 := flag.String("hash", "", "Hash to verify against (base64)")
	hashSize := flag.Int("size", 256, "Hash size: 256, 384, 512, or 1024 bits")
	flag.Parse()

	// Validate hash size
	validSizes := map[int]bool{256: true, 384: true, 512: true, 1024: true}
	if !validSizes[*hashSize] {
		fmt.Fprintf(os.Stderr, "Invalid hash size. Supported sizes: 256, 384, 512, 1024\n")
		os.Exit(1)
	}

	hasher, err := qhash.NewHardenedLorenzHasher(*hashSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize hasher: %v\n", err)
		os.Exit(1)
	}

	// Input validation and data loading
	var inputData []byte
	if *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read file %s: %v\n", *file, err)
			os.Exit(1)
		}
		inputData = data
		fmt.Printf("Loaded file: %s (%d bytes)\n", *file, len(data))
	} else if *in != "" {
		inputData = []byte(*in)
	}

	if (*genH || *gen) && len(inputData) == 0 {
		fmt.Fprintf(os.Stderr, "Error: input or file required for hash generation\n")
		flag.Usage()
		os.Exit(1)
	}

	if *genH && len(inputData) > 0 {
		out, err := hasher.HashWithHardening(inputData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Hashing failed: %v\n", err)
			os.Exit(1)
		}
		j, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON encoding failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("QHASH-%d\nHEX: %x\nMEM: %dKB\nTIME: %dms\nJSON:\n%s\nB64:\n%s\n",
			*hashSize, out.Hash, out.MemoryUsed, out.ComputeTime/1e6,
			j, base64.StdEncoding.EncodeToString(j),
		)
		return
	}

	if *gen && len(inputData) > 0 {
		h, err := hasher.Hash(inputData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Hashing failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("QHASH-%d\nHEX: %x\nB64: %s\n",
			*hashSize, h, base64.StdEncoding.EncodeToString(h),
		)
		return
	}

	// Verification logic
	var verifyData []byte
	if *verifyFile != "" {
		data, err := os.ReadFile(*verifyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read verify file %s: %v\n", *verifyFile, err)
			os.Exit(1)
		}
		verifyData = data
	} else if *vr != "" {
		verifyData = []byte(*vr)
	}

	if len(verifyData) > 0 && *hjson != "" {
		if err := verifyHardenedHash(verifyData, *hjson, hasher); err != nil {
			fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(verifyData) > 0 && *hash64 != "" {
		if err := verifyLegacyHash(verifyData, *hash64, hasher); err != nil {
			fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *graphics {
		if err := runGraphics(hasher); err != nil {
			fmt.Fprintf(os.Stderr, "Graphics error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	flag.Usage()
}

func verifyHardenedHash(data []byte, hjson string, hasher *qhash.HardenedLorenzHasher) error {
	raw, err := base64.StdEncoding.DecodeString(hjson)
	if err != nil {
		// Try as raw JSON if base64 decode fails
		raw = []byte(hjson)
	}

	var stored qhash.HardenedSaltedHash
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("JSON decode error: %w", err)
	}

	ok, err := hasher.VerifyHardenedHash(data, &stored)
	if err != nil {
		return fmt.Errorf("verification error: %w", err)
	}

	fmt.Println("Hardened OK:", ok)
	return nil
}

func verifyLegacyHash(data []byte, hash64 string, hasher *qhash.HardenedLorenzHasher) error {
	expected, err := base64.StdEncoding.DecodeString(hash64)
	if err != nil {
		return fmt.Errorf("base64 decode error: %w", err)
	}

	got, err := hasher.Hash(data)
	if err != nil {
		return fmt.Errorf("hashing error: %w", err)
	}

	ok := bytes.Equal(got, expected)
	fmt.Println("Legacy OK:", ok)
	return nil
}

type LorenzRenderer struct {
	points                 []qhash.Point3D
	trail                  []qhash.Point3D
	angleX, angleY, angleZ float64
	x, y, z                float64
	params                 LorenzParams
	trailLength            int
	frameCount             int
	autoRotate             bool
	hashSize               int
}

type LorenzParams struct {
	sigma, rho, beta, dt float64
}

// Enhanced Lorenz parameter sets for different hash sizes
var lorenzPresets = map[int][]LorenzParams{
	256: {
		{10.0, 28.0, 8.0 / 3.0, 0.01}, // Classic
		{16.0, 45.6, 4.0, 0.008},      // Energetic
	},
	384: {
		{10.0, 28.0, 8.0 / 3.0, 0.01}, // Classic
		{16.0, 45.6, 4.0, 0.008},      // Energetic
		{12.5, 35.2, 2.5, 0.012},      // Wide
	},
	512: {
		{10.0, 28.0, 8.0 / 3.0, 0.01}, // Classic
		{16.0, 45.6, 4.0, 0.008},      // Energetic
		{12.5, 35.2, 2.5, 0.012},      // Wide
		{8.5, 24.8, 6.2, 0.015},       // Compact
	},
	1024: {
		{10.0, 28.0, 8.0 / 3.0, 0.01}, // Classic
		{16.0, 45.6, 4.0, 0.008},      // Energetic
		{12.5, 35.2, 2.5, 0.012},      // Wide
		{8.5, 24.8, 6.2, 0.015},       // Compact
		{14.2, 32.1, 3.8, 0.009},      // Extended-1
		{11.7, 41.3, 5.1, 0.011},      // Extended-2
		{9.3, 26.7, 7.4, 0.013},       // Extended-3
		{13.8, 38.9, 2.9, 0.007},      // Extended-4
	},
}

func NewLorenzRenderer(hashSize int) *LorenzRenderer {
	presets, exists := lorenzPresets[hashSize]
	if !exists {
		presets = lorenzPresets[256] // fallback
	}

	preset := presets[time.Now().UnixNano()%int64(len(presets))]

	// Small random perturbations based on hash size
	r := time.Now().UnixNano()
	sizeMultiplier := float64(hashSize) / 256.0
	preset.sigma += (float64((r>>8)%50)/100.0 - 0.25) * 2.0 * sizeMultiplier
	preset.rho += (float64((r>>16)%50)/100.0 - 0.25) * 3.0 * sizeMultiplier

	// Random initial conditions scaled by hash size
	x := (float64((r>>32)%100)/100.0 - 0.5) * 15.0 * sizeMultiplier
	y := (float64((r>>40)%100)/100.0 - 0.5) * 15.0 * sizeMultiplier
	z := (float64((r>>48)%100)/100.0 - 0.5) * 15.0 * sizeMultiplier

	baseTrail := 120
	trailLength := int(float64(baseTrail) * sizeMultiplier)
	if trailLength < 60 {
		trailLength = 60
	}
	if trailLength > 300 {
		trailLength = 300
	}

	return &LorenzRenderer{
		points: make([]qhash.Point3D, 0, 3000*int(sizeMultiplier)),
		trail:  make([]qhash.Point3D, 0, trailLength),
		x:      x, y: y, z: z,
		params:      preset,
		trailLength: trailLength,
		autoRotate:  true,
		hashSize:    hashSize,
	}
}

func (lr *LorenzRenderer) update() {
	// Evolve Lorenz system
	dx := lr.params.sigma * (lr.y - lr.x)
	dy := lr.x*(lr.params.rho-lr.z) - lr.y
	dz := lr.x*lr.y - lr.params.beta*lr.z

	lr.x += dx * lr.params.dt
	lr.y += dy * lr.params.dt
	lr.z += dz * lr.params.dt

	// Add to trail
	newPoint := qhash.Point3D{X: lr.x, Y: lr.y, Z: lr.z}
	lr.trail = append(lr.trail, newPoint)

	if len(lr.trail) > lr.trailLength {
		removeCount := len(lr.trail) - lr.trailLength
		if removeCount > 40 {
			removeCount = 40
		}
		lr.trail = lr.trail[removeCount:]
	}

	// Add to permanent points less frequently for larger hash sizes
	skipFrames := 5
	if lr.hashSize >= 512 {
		skipFrames = 3
	}
	if lr.hashSize >= 1024 {
		skipFrames = 2
	}

	if lr.frameCount%skipFrames == 0 && len(lr.points) < cap(lr.points) {
		lr.points = append(lr.points, newPoint)
	}

	// Auto-rotation speeds based on hash size
	rotSpeed := 1.0
	if lr.hashSize >= 384 {
		rotSpeed = 1.2
	}
	if lr.hashSize >= 512 {
		rotSpeed = 1.4
	}
	if lr.hashSize >= 1024 {
		rotSpeed = 1.6
	}

	if lr.autoRotate {
		lr.angleX += 0.008 * rotSpeed
		lr.angleY += 0.012 * rotSpeed
		lr.angleZ += 0.006 * rotSpeed
	}

	lr.frameCount++
}

// Multiple shading character sets for different visual styles
var shadingStyles = [][]rune{
	// Heavy to light blocks
	{'█', '▉', '▊', '▋', '▌', '▍', '▎', '▏', '░', '▒', '▓', '·', '˙', ' '},
	// Circle variations
	{'●', '◉', '◎', '○', '◌', '◦', '∘', '·', '˙', '.'},
	// ASCII traditional
	{'@', '#', '&', '%', '$', 'W', 'M', 'H', '8', '0', 'Q', 'O', 'o', '*', '+', '=', '-', '^', ':', '.', ' '},
	// Dots and marks
	{'▪', '▫', '■', '□', '●', '○', '▲', '△', '♦', '◊', '▬', '▭', '·', '˙', ' '},
}

func getDepthCharWithStyle(depth float64, style int) rune {
	if depth < 0 {
		depth = 0
	}
	if depth > 1 {
		depth = 1
	}

	chars := shadingStyles[style%len(shadingStyles)]
	idx := int(depth * float64(len(chars)-1))
	return chars[idx]
}

// Enhanced color interpolation with hash-size specific palettes
func interpolateColorWithDepth(t, depth float64, hashSize int) tcell.Color {
	if t < 0 {
		t = 0
	}
	if t > 1 {
		t = 1
	}
	if depth < 0 {
		depth = 0
	}
	if depth > 1 {
		depth = 1
	}

	// Different color palettes for different hash sizes
	var r1, g1, b1, r2, g2, b2, r3, g3, b3 int

	switch hashSize {
	case 256:
		// Classic purple-orange-green
		r1, g1, b1 = 120, 80, 255 // Deep purple
		r2, g2, b2 = 255, 150, 50 // Orange
		r3, g3, b3 = 50, 255, 120 // Green
	case 384:
		// Blue-cyan-yellow
		r1, g1, b1 = 50, 100, 255 // Deep blue
		r2, g2, b2 = 50, 255, 200 // Cyan
		r3, g3, b3 = 255, 255, 50 // Yellow
	case 512:
		// Red-magenta-blue
		r1, g1, b1 = 255, 50, 80  // Red
		r2, g2, b2 = 255, 50, 255 // Magenta
		r3, g3, b3 = 80, 150, 255 // Blue
	case 1024:
		// Enhanced rainbow spectrum
		r1, g1, b1 = 255, 50, 150 // Pink
		r2, g2, b2 = 150, 255, 50 // Lime
		r3, g3, b3 = 50, 150, 255 // Sky blue
	default:
		// Fallback to 256 colors
		r1, g1, b1 = 120, 80, 255
		r2, g2, b2 = 255, 150, 50
		r3, g3, b3 = 50, 255, 120
	}

	// Interpolate through three colors based on position
	var r, g, b int
	if t < 0.5 {
		// First to second color
		blend := t * 2
		r = int(float64(r1) + blend*float64(r2-r1))
		g = int(float64(g1) + blend*float64(g2-g1))
		b = int(float64(b1) + blend*float64(b2-b1))
	} else {
		// Second to third color
		blend := (t - 0.5) * 2
		r = int(float64(r2) + blend*float64(r3-r2))
		g = int(float64(g2) + blend*float64(g3-g2))
		b = int(float64(b2) + blend*float64(b3-b2))
	}

	// Apply dramatic depth-based darkening/brightening
	depthFactor := 0.2 + 0.8*depth // Range from 20% to 100% brightness
	r = int(float64(r) * depthFactor)
	g = int(float64(g) * depthFactor)
	b = int(float64(b) * depthFactor)

	// Ensure values stay in valid range
	if r > 255 {
		r = 255
	}
	if g > 255 {
		g = 255
	}
	if b > 255 {
		b = 255
	}
	if r < 0 {
		r = 0
	}
	if g < 0 {
		g = 0
	}
	if b < 0 {
		b = 0
	}

	return tcell.NewRGBColor(int32(r), int32(g), int32(b))
}

// Enhanced rendering with hash-size specific adaptations
func (lr *LorenzRenderer) renderWithEnhancedShading(s tcell.Screen, w, h int, currentStyle int) {
	// Enhanced UI with hash size information
	style := tcell.StyleDefault.Foreground(tcell.ColorWhite)
	uiText := fmt.Sprintf("QHASH-%d Lorenz | Arrows:rotate A:auto N:new S:style +/-:trail Q:quit", lr.hashSize)
	drawText(s, 1, 1, style, uiText)

	// Scale rendering based on hash size and screen
	baseScale := math.Min(float64(w)/100.0, float64(h)/75.0) * 0.5
	sizeScale := 1.0 + (float64(lr.hashSize)/256.0-1.0)*0.3 // Slightly larger for bigger hashes
	scale := baseScale * sizeScale

	centerX, centerY := float64(w)/2, float64(h)/2

	type renderPoint struct {
		x, y     int
		z        float64
		char     rune
		color    tcell.Color
		priority int
	}

	var renderPoints []renderPoint

	// Calculate depth range for better normalization
	minZ, maxZ := math.Inf(1), math.Inf(-1)
	allPoints := append(lr.points, lr.trail...)
	for _, p := range allPoints {
		rot := p.Rotate(lr.angleX, lr.angleY, lr.angleZ)
		if rot.Z < minZ {
			minZ = rot.Z
		}
		if rot.Z > maxZ {
			maxZ = rot.Z
		}
	}
	depthRange := maxZ - minZ
	if depthRange == 0 {
		depthRange = 1
	}

	// Background effects scaled by hash size
	bgDensity := w * h / (200 - lr.hashSize/20)
	if lr.frameCount%10 == 0 {
		for i := 0; i < bgDensity; i++ {
			seed := lr.frameCount/10 + i*7919
			x := (seed*1664525 + 1013904223) % w
			y := ((seed>>8)*1664525+1013904223)%(h-4) + 3

			intensity := 25 + lr.hashSize/40
			bgColor := tcell.NewRGBColor(int32(intensity), int32(intensity), int32(intensity))
			char := '·'
			if (seed>>16)%10 == 0 {
				bgColor = tcell.NewRGBColor(int32(intensity+10), int32(intensity+10), int32(intensity+20))
				char = '˙'
			}

			renderPoints = append(renderPoints, renderPoint{
				x: int(x), y: int(y), z: -1000,
				char: char, color: bgColor, priority: 0})
		}
	}

	// Render main attractor points
	for i, p := range lr.points {
		rot := p.Rotate(lr.angleX, lr.angleY, lr.angleZ)
		sx := int(rot.X*scale + centerX)
		sy := int(rot.Y*scale + centerY)

		if sx >= 0 && sx < w && sy >= 3 && sy < h-1 {
			normalizedDepth := (rot.Z - minZ) / depthRange
			colorT := float64(i) / float64(len(lr.points))
			color := interpolateColorWithDepth(colorT, normalizedDepth, lr.hashSize)
			char := getDepthCharWithStyle(normalizedDepth, currentStyle)

			renderPoints = append(renderPoints, renderPoint{
				x: sx, y: sy, z: rot.Z,
				char: char, color: color, priority: 1})
		}
	}

	// Enhanced trail rendering
	trailLen := len(lr.trail)
	for i, p := range lr.trail {
		rot := p.Rotate(lr.angleX, lr.angleY, lr.angleZ)
		sx := int(rot.X*scale + centerX)
		sy := int(rot.Y*scale + centerY)

		if sx >= 0 && sx < w && sy >= 1 && sy < h-1 {
			normalizedDepth := (rot.Z - minZ) / depthRange
			trailIntensity := float64(i) / float64(trailLen)
			combinedIntensity := normalizedDepth * (0.3 + 0.7*trailIntensity)

			color := interpolateColorWithDepth(0.9, combinedIntensity, lr.hashSize)

			var char rune
			if i >= trailLen-4 {
				char = '◉'
			} else if i >= trailLen-8 {
				char = '●'
			} else {
				char = getDepthCharWithStyle(combinedIntensity, 1)
			}

			renderPoints = append(renderPoints, renderPoint{
				x: sx, y: sy, z: rot.Z,
				char: char, color: color, priority: 2})
		}
	}

	// Sort by priority and depth
	for i := 0; i < len(renderPoints)-1; i++ {
		for j := i + 1; j < len(renderPoints); j++ {
			if renderPoints[i].priority > renderPoints[j].priority ||
				(renderPoints[i].priority == renderPoints[j].priority && renderPoints[i].z > renderPoints[j].z) {
				renderPoints[i], renderPoints[j] = renderPoints[j], renderPoints[i]
			}
		}
	}

	// Render all points
	for _, p := range renderPoints {
		s.SetContent(p.x, p.y, p.char, nil, tcell.StyleDefault.Foreground(p.color))
	}

	// Enhanced status display
	info := fmt.Sprintf("QHASH-%d | Points: %d | Trail: %d | Style: %d | Frame: %d",
		lr.hashSize, len(lr.points), len(lr.trail), currentStyle+1, lr.frameCount)
	drawText(s, 1, h-2, tcell.StyleDefault.Foreground(tcell.ColorDarkGray), info)
}

func runGraphics(hasher *qhash.HardenedLorenzHasher) error {
	s, err := tcell.NewScreen()
	if err != nil {
		return fmt.Errorf("screen init failed: %w", err)
	}
	if err := s.Init(); err != nil {
		return fmt.Errorf("screen start failed: %w", err)
	}
	defer s.Fini()

	renderer := NewLorenzRenderer(hasher.GetHashSize())
	quit := make(chan struct{})
	currentStyle := 2

	// Input handler
	go func() {
		defer close(quit)
		for {
			select {
			case <-quit:
				return
			default:
				ev := s.PollEvent()
				switch ev := ev.(type) {
				case *tcell.EventKey:
					switch ev.Key() {
					case tcell.KeyEscape, tcell.KeyCtrlC:
						return
					case tcell.KeyUp:
						renderer.angleX -= 0.15
					case tcell.KeyDown:
						renderer.angleX += 0.15
					case tcell.KeyLeft:
						renderer.angleY -= 0.15
					case tcell.KeyRight:
						renderer.angleY += 0.15
					case tcell.KeyRune:
						switch ev.Rune() {
						case 'q', 'Q':
							return
						case 'r':
							renderer.angleX, renderer.angleY, renderer.angleZ = 0, 0, 0
						case 'a':
							renderer.autoRotate = !renderer.autoRotate
						case 'n':
							*renderer = *NewLorenzRenderer(renderer.hashSize)
						case 's', 'S':
							currentStyle = (currentStyle + 1) % len(shadingStyles)
						case ' ':
							renderer.autoRotate = !renderer.autoRotate
						case '+', '=':
							if renderer.trailLength < 400 {
								renderer.trailLength += 20
							}
						case '-', '_':
							if renderer.trailLength > 20 {
								renderer.trailLength -= 20
							}
						}
					}
				case *tcell.EventResize:
					s.Sync()
				}
			}
		}
	}()

	// Render loop
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-quit:
			return nil
		case <-ticker.C:
			renderer.update()
			s.Clear()
			w, h := s.Size()

			if w <= 15 || h <= 8 {
				continue
			}

			renderer.renderWithEnhancedShading(s, w, h, currentStyle)
			s.Show()
		}
	}
}

func drawText(s tcell.Screen, x, y int, style tcell.Style, str string) {
	for i, r := range str {
		s.SetContent(x+i, y, r, nil, style)
	}
}
