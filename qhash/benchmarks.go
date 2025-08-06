// =======================
// qhash/benchmarks.go
// =======================

package qhash

import (
	"fmt"
	"time"
)

// BenchmarkInfo holds performance metrics
type BenchmarkInfo struct {
	HashSize    int           `json:"hash_size"`
	DataSize    int           `json:"data_size_bytes"`
	ComputeTime time.Duration `json:"compute_time"`
	MemoryUsed  int           `json:"memory_used_kb"`
	Throughput  float64       `json:"throughput_mbps"`
	EntropyRate float64       `json:"entropy_rate_bits_per_second"`
}

// BenchmarkHasher tests performance of different hash sizes
func BenchmarkHasher(data []byte, iterations int) ([]BenchmarkInfo, error) {
	sizes := []int{256, 384, 512, 1024}
	results := make([]BenchmarkInfo, 0, len(sizes))

	for _, size := range sizes {
		hasher, err := NewHardenedLorenzHasher(size)
		if err != nil {
			return nil, fmt.Errorf("failed to create hasher for size %d: %w", size, err)
		}

		start := time.Now()
		var totalMemory int

		for i := 0; i < iterations; i++ {
			result, err := hasher.HashWithHardening(data)
			if err != nil {
				return nil, fmt.Errorf("hashing failed at iteration %d: %w", i, err)
			}
			totalMemory += result.MemoryUsed
		}

		duration := time.Since(start)
		avgMemory := totalMemory / iterations

		// Calculate throughput in MB/s
		totalBytes := float64(len(data) * iterations)
		seconds := duration.Seconds()
		throughput := (totalBytes / (1024 * 1024)) / seconds

		// Calculate entropy rate (bits processed per second)
		totalBits := float64(len(data) * iterations * 8)
		entropyRate := totalBits / seconds

		results = append(results, BenchmarkInfo{
			HashSize:    size,
			DataSize:    len(data),
			ComputeTime: duration / time.Duration(iterations),
			MemoryUsed:  avgMemory,
			Throughput:  throughput,
			EntropyRate: entropyRate,
		})
	}

	return results, nil
}

// PrintBenchmarkResults displays benchmark results in a formatted table
func PrintBenchmarkResults(results []BenchmarkInfo) {
	fmt.Println("QHASH Performance Benchmark Results")
	fmt.Println("===================================")
	fmt.Printf("%-8s | %-12s | %-10s | %-12s | %-15s\n",
		"Size", "Time/Hash", "Memory", "Throughput", "Entropy Rate")
	fmt.Println("---------|--------------|------------|--------------|----------------")

	for _, result := range results {
		fmt.Printf("%-8d | %-12s | %-10d | %-12.2f | %-15.0f\n",
			result.HashSize,
			result.ComputeTime.String(),
			result.MemoryUsed,
			result.Throughput,
			result.EntropyRate)
	}
}
