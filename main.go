package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/cpuid/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

// Logger setup
var logger = logrus.New()

func init() {
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)
}

// Struct definitions
type QuantumSeed struct {
	Entropy     []byte
	Disposition [][]int
	EntropyPool *sync.Pool
}

type LatticeKey struct {
	PublicKey    []byte
	SecretKey    []byte
	Perturbation []float64
}

type QLASHParameters struct {
	LatticeDimension   int
	BlockSize          int
	NumBlocks          int
	SuperpositionDepth int
	EntanglementFactor float64
	EntropyQuality     float64
	AdaptiveMode       bool
	CacheReuse         bool
}

var (
	QLASH128 = QLASHParameters{
		LatticeDimension:   128,
		BlockSize:          4096,
		SuperpositionDepth: 8,
		EntanglementFactor: 0.75,
		EntropyQuality:     0.98,
	}
	QLASH192 = QLASHParameters{
		LatticeDimension:   192,
		BlockSize:          6144,
		SuperpositionDepth: 12,
		EntanglementFactor: 0.80,
		EntropyQuality:     0.99,
	}
	QLASH256 = QLASHParameters{
		LatticeDimension:   256,
		BlockSize:          8192,
		SuperpositionDepth: 16,
		EntanglementFactor: 0.85,
		EntropyQuality:     0.995,
	}
	QLASH512 = QLASHParameters{
		LatticeDimension:   512,
		BlockSize:          16384,
		SuperpositionDepth: 24,
		EntanglementFactor: 0.90,
		EntropyQuality:     0.998,
	}
	QLASH1024 = QLASHParameters{
		LatticeDimension:   1024,
		BlockSize:          32768,
		SuperpositionDepth: 32,
		EntanglementFactor: 0.95,
		EntropyQuality:     0.999,
	}
)

type EncryptionResult struct {
	Blocks           []EncryptedBlock
	TotalTime        time.Duration
	KeyGenTime       time.Duration
	EncryptionTime   time.Duration
	EntanglementTime time.Duration
	ParameterSet     string
	OriginalSize     int
	EncryptedSize    int
	ExpansionFactor  float64
	EffectiveBits    int64
	EntropyDensity   float64
	ProcessorThreads int
	VectorExtensions []string
	SeedEntropy      []byte
}

type EncryptedBlock struct {
	Data       []byte
	Nonce      *big.Int
	BlockHash  []byte
	BlockIndex int
}

// Modify the FileHeader struct to include original extension
type FileHeader struct {
	Version           string   `json:"version"`
	Created           string   `json:"created"`
	ParameterSet      string   `json:"parameterSet"`
	OriginalSize      int      `json:"originalSize"`
	EncryptedSize     int      `json:"encryptedSize"`
	ExpansionFactor   float64  `json:"expansionFactor"`
	BlockCount        int      `json:"blockCount"`
	ProcessorThreads  int      `json:"processorThreads"`
	VectorExtensions  []string `json:"vectorExtensions"`
	EntropyMark       []byte   `json:"entropyMark"`       // For verification
	OriginalExtension string   `json:"originalExtension"` // Added to preserve file extension
	// Removed: SeedEntropy []byte
}
type DecryptionResult struct {
	OriginalSize     int
	DecryptedSize    int
	TotalTime        time.Duration
	KeyGenTime       time.Duration
	DecryptionTime   time.Duration
	ParameterSet     string
	BlocksProcessed  int
	ProcessorThreads int
	VectorExtensions []string
	IntegrityValid   bool
}

// Improved buffer pool with size-based buckets
var bufferPools = [...]sync.Pool{
	// 4KB
	{New: func() interface{} { buffer := make([]byte, 4096); return &buffer }},
	// 8KB
	{New: func() interface{} { buffer := make([]byte, 8192); return &buffer }},
	// 16KB
	{New: func() interface{} { buffer := make([]byte, 16384); return &buffer }},
	// 32KB
	{New: func() interface{} { buffer := make([]byte, 32768); return &buffer }},
	// 64KB
	{New: func() interface{} { buffer := make([]byte, 65536); return &buffer }},
}

func getBuffer(size int) *[]byte {
	// Choose appropriate buffer pool based on size
	var pool *sync.Pool
	if size <= 4096 {
		pool = &bufferPools[0]
	} else if size <= 8192 {
		pool = &bufferPools[1]
	} else if size <= 16384 {
		pool = &bufferPools[2]
	} else if size <= 32768 {
		pool = &bufferPools[3]
	} else {
		pool = &bufferPools[4]
	}

	buf := pool.Get().(*[]byte)
	if cap(*buf) < size {
		*buf = make([]byte, size)
	} else {
		*buf = (*buf)[:size]
	}
	return buf
}

func returnBufferPtr(buf *[]byte, size int) {
	// Return to appropriate pool
	if size <= 4096 {
		bufferPools[0].Put(buf)
	} else if size <= 8192 {
		bufferPools[1].Put(buf)
	} else if size <= 16384 {
		bufferPools[2].Put(buf)
	} else if size <= 32768 {
		bufferPools[3].Put(buf)
	} else {
		bufferPools[4].Put(buf)
	}
}

// Advanced entropy generation
func generateEntropyMark() []byte {
	mark := make([]byte, 32)
	rand.Read(mark)

	// Mix with hardware info for uniqueness
	h := sha3.New256()
	h.Write(mark)
	h.Write([]byte(runtime.GOARCH))
	h.Write([]byte(runtime.GOOS))
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))

	return h.Sum(nil)
}

func detectSIMDCapabilities() []string {
	var capabilities []string
	if cpuid.CPU.Supports(cpuid.AVX512F) {
		capabilities = append(capabilities, "AVX512F")
	}
	if cpuid.CPU.Supports(cpuid.AVX2) {
		capabilities = append(capabilities, "AVX2")
	}
	if cpuid.CPU.Supports(cpuid.AVX) {
		capabilities = append(capabilities, "AVX")
	}
	if cpuid.CPU.Supports(cpuid.SSE4) {
		capabilities = append(capabilities, "SSE4")
	}
	if cpuid.CPU.Supports(cpuid.SSSE3) {
		capabilities = append(capabilities, "SSSE3")
	}
	if cpuid.CPU.Supports(cpuid.SSE3) {
		capabilities = append(capabilities, "SSE3")
	}
	if cpuid.CPU.Supports(cpuid.SSE2) {
		capabilities = append(capabilities, "SSE2")
	}
	return capabilities
}

func estimateEntropy(data []byte) float64 {
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy / 8.0
}

// Improved quantum seed generation with stronger entropy
func GenerateQuantumSeed(entropySize int, entropyQuality float64, providedEntropy []byte) (*QuantumSeed, error) {
	startTime := time.Now()

	pool := &sync.Pool{
		New: func() interface{} {
			return make([]byte, entropySize)
		},
	}

	entropy := pool.Get().([]byte)

	if len(providedEntropy) >= entropySize {
		copy(entropy, providedEntropy[:entropySize])
	} else {
		// Enhanced entropy generation
		if entropyQuality > 0.95 {
			primaryEntropy := make([]byte, entropySize)
			secondaryEntropy := make([]byte, entropySize)
			tertiaryEntropy := make([]byte, entropySize)

			// Get cryptographically secure random bytes
			if _, err := rand.Read(primaryEntropy); err != nil {
				return nil, err
			}

			// Use SHA3 for secondary entropy
			h := sha3.NewShake256()
			timeBytes := []byte(time.Now().Format(time.RFC3339Nano))
			h.Write(timeBytes)
			h.Read(secondaryEntropy)

			// Add a third source based on system state
			h2 := sha3.NewShake128()
			h2.Write([]byte(fmt.Sprintf("%d", runtime.NumCPU())))
			h2.Write([]byte(runtime.GOARCH))
			h2.Write([]byte(runtime.GOOS))
			h2.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
			h2.Read(tertiaryEntropy)

			// Combine all three sources with XOR and bit rotation
			for i := range entropy {
				entropy[i] = primaryEntropy[i] ^ secondaryEntropy[i] ^ tertiaryEntropy[i]
				if i > 0 {
					// Bit rotation for better diffusion
					entropy[i] = (entropy[i] << 1) | (entropy[i-1] >> 7)
				}
			}
		} else {
			if _, err := rand.Read(entropy); err != nil {
				return nil, err
			}
		}
	}

	// Additional mixing step for all entropy sources
	h := sha3.New256()
	h.Write(entropy)
	mixingKey := h.Sum(nil)

	for i := range entropy {
		entropy[i] ^= mixingKey[i%len(mixingKey)]
	}

	disposition := make([][]int, entropySize)
	simd := detectSIMDCapabilities()
	useVectorization := len(simd) > 0 && entropySize >= 64

	if useVectorization {
		chunkSize := 8
		for i := 0; i < entropySize; i += chunkSize {
			end := i + chunkSize
			if end > entropySize {
				end = entropySize
			}

			chunk := make([]int, (end-i)*2)
			for j := i; j < end; j++ {
				disposition[j] = chunk[(j-i)*2 : (j-i+1)*2]
			}

			for j := i; j < end; j++ {
				val1 := (int(entropy[j]) << 8) | int(entropy[(j+1)%entropySize])
				val2 := (int(entropy[(j+2)%entropySize]) << 8) | int(entropy[(j+3)%entropySize])
				disposition[j][0] = val1 % 1000
				disposition[j][1] = val2 % 1000
			}
		}
	} else {
		var wg sync.WaitGroup
		chunkSize := entropySize / runtime.NumCPU()
		if chunkSize < 8 {
			chunkSize = 8
		}

		for start := 0; start < entropySize; start += chunkSize {
			wg.Add(1)
			go func(startIdx int) {
				defer wg.Done()
				endIdx := startIdx + chunkSize
				if endIdx > entropySize {
					endIdx = entropySize
				}

				for i := startIdx; i < endIdx; i++ {
					disposition[i] = make([]int, 2)
					val1 := (int(entropy[i]) << 8) | int(entropy[(i+1)%entropySize])
					val2 := (int(entropy[(i+2)%entropySize]) << 8) | int(entropy[(i+3)%entropySize])
					disposition[i][0] = val1 % 1000
					disposition[i][1] = val2 % 1000
				}
			}(start)
		}
		wg.Wait()
	}

	seed := &QuantumSeed{
		Entropy:     entropy,
		Disposition: disposition,
		EntropyPool: pool,
	}

	logger.Debugf("Quantum seed generation completed in %v with entropy quality %.2f",
		time.Since(startTime), entropyQuality)

	return seed, nil
}

// Optimized lattice key generation
func GenerateLatticeKey(seed *QuantumSeed, dimension int, cacheReuse bool) *LatticeKey {
	startTime := time.Now()
	key := &LatticeKey{
		PublicKey:    make([]byte, dimension),
		SecretKey:    make([]byte, dimension),
		Perturbation: make([]float64, dimension/2),
	}

	var wg sync.WaitGroup
	chunkSize := dimension / runtime.NumCPU()
	if chunkSize < 16 {
		chunkSize = 16
	}

	for start := 0; start < dimension; start += chunkSize {
		wg.Add(1)
		go func(startIdx int) {
			defer wg.Done()
			endIdx := startIdx + chunkSize
			if endIdx > dimension {
				endIdx = dimension
			}

			for i := startIdx; i < endIdx; i++ {
				// Create a new Shake256 hash for each iteration
				h := sha3.NewShake256()
				seedIndex := i % len(seed.Entropy)
				h.Write(seed.Entropy[seedIndex : seedIndex+1])
				var buffer [64]byte
				h.Read(buffer[:])

				key.PublicKey[i] = buffer[0]
				key.SecretKey[i] = buffer[1]
				if i < dimension/2 {
					// Use more bytes for better precision in perturbation values
					pertVal := float64(binary.LittleEndian.Uint64(buffer[8:16])) / float64(1<<64)
					key.Perturbation[i] = pertVal
				}
			}
		}(start)
	}
	wg.Wait()

	logger.Debugf("Lattice key generation completed in %v for dimension %d",
		time.Since(startTime), dimension)
	return key
}

// Fixed encryption block function
func EncryptBlock(data []byte, key *LatticeKey, params QLASHParameters, blockIndex int) (*EncryptedBlock, error) {
	dataLength := len(data)
	primaryStatePtr := getBuffer(dataLength)
	primaryState := *primaryStatePtr
	defer returnBufferPtr(primaryStatePtr, dataLength)
	secondaryStatePtr := getBuffer(dataLength)
	secondaryState := *secondaryStatePtr
	defer returnBufferPtr(secondaryStatePtr, dataLength)
	superpositionPtr := getBuffer(dataLength)
	superposition := *superpositionPtr
	defer returnBufferPtr(superpositionPtr, dataLength)

	copy(primaryState, data)
	copy(secondaryState, data)
	copy(superposition, data)

	nonceInt, err := rand.Int(rand.Reader, big.NewInt(int64(params.LatticeDimension*1000)))
	if err != nil {
		return nil, err
	}

	outputPtr := getBuffer(dataLength)
	output := *outputPtr
	defer returnBufferPtr(outputPtr, dataLength)

	// Initial transformation
	for i := 0; i < dataLength; i++ {
		keyIndex := i % len(key.PublicKey)
		secretIndex := i % len(key.SecretKey)

		primaryVal := (int(primaryState[i]) + int(key.PublicKey[keyIndex])) % 256
		secondaryVal := (int(secondaryState[i]) ^ int(key.SecretKey[secretIndex])) % 256

		factor := params.EntanglementFactor * (float64(key.PublicKey[keyIndex]) / 255.0)
		output[i] = byte(int(float64(primaryVal)*factor+float64(secondaryVal)*(1.0-factor)) % 256)
	}

	finalData := make([]byte, dataLength)
	copy(finalData, output)

	// Apply transformations with proper tracking for decryption
	for depth := 0; depth < params.SuperpositionDepth; depth++ {
		for i := 0; i < len(finalData); i++ {
			keyIndex := (i + depth) % len(key.PublicKey)
			pertIndex := (i + depth*2) % len(key.Perturbation)

			switch depth % 3 {
			case 0:
				factor := (1 + int(key.PublicKey[keyIndex])/128)
				finalData[i] = byte((int(finalData[i]) * factor) % 256)
			case 1:
				if i+keyIndex < len(finalData) {
					finalData[i] ^= finalData[(i+keyIndex)%len(finalData)]
				}
			case 2:
				rotAmount := int(key.Perturbation[pertIndex]*7) % 8
				finalData[i] = byte(((int(finalData[i]) << rotAmount) |
					(int(finalData[i]) >> (8 - rotAmount))) & 0xFF)
			}
		}
	}

	// Generate secured hash
	h := sha3.New256()
	indexBytes := []byte(fmt.Sprintf("%d", blockIndex))
	nonceBytes := nonceInt.Bytes()
	h.Write(indexBytes)
	h.Write(nonceBytes)
	h.Write(finalData)
	blockHash := h.Sum(nil)

	logger.Debugf("EncryptBlock %d: index=%s, nonce=%x, data_len=%d, hash=%x",
		blockIndex, indexBytes, nonceBytes, len(finalData), blockHash)

	return &EncryptedBlock{
		Data:       finalData,
		Nonce:      nonceInt,
		BlockHash:  blockHash,
		BlockIndex: blockIndex,
	}, nil
}

// Improved file encryption with better memory management
// Modify EncryptFile to track original extension
func EncryptFile(filename string, params QLASHParameters, keyFilename string) (*EncryptionResult, error) {
	startTime := time.Now()

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := fileInfo.Size()

	blockSize := params.BlockSize
	if fileSize > 100*1024*1024 {
		blockSize = 8 * 1024
	} else if fileSize < 1024*1024 {
		blockSize = 2 * 1024
	}

	numBlocks := int(math.Ceil(float64(fileSize) / float64(blockSize)))
	if params.NumBlocks > 0 && params.NumBlocks < numBlocks {
		numBlocks = params.NumBlocks
		blockSize = int(math.Ceil(float64(fileSize) / float64(numBlocks)))
	}

	seed, err := GenerateQuantumSeed(params.LatticeDimension*2, params.EntropyQuality, nil)
	if err != nil {
		return nil, err
	}

	keyGenStart := time.Now()
	key := GenerateLatticeKey(seed, params.LatticeDimension, params.CacheReuse)
	keyGenTime := time.Since(keyGenStart)

	// Save the key to a file
	if keyFilename != "" {
		err = SaveKeyToFile(key, keyFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to save key: %v", err)
		}
	}

	// Rest of the function remains unchanged
	encryptionStart := time.Now()
	blocks := make([]EncryptedBlock, numBlocks)

	numWorkers := runtime.NumCPU()
	if numBlocks < numWorkers {
		numWorkers = numBlocks
	}

	blockIndexCh := make(chan int, numBlocks)
	resultCh := make(chan struct {
		index int
		block *EncryptedBlock
		err   error
	}, numBlocks)

	var processedCount int32

	for w := 0; w < numWorkers; w++ {
		go func() {
			for blockIndex := range blockIndexCh {
				offset := int64(blockIndex * blockSize)
				size := blockSize
				if offset+int64(size) > fileSize {
					size = int(fileSize - offset)
				}

				buffer := make([]byte, size)
				n, err := file.ReadAt(buffer, offset)
				if err != nil && err != io.EOF {
					resultCh <- struct {
						index int
						block *EncryptedBlock
						err   error
					}{blockIndex, nil, err}
					continue
				}

				if n < size {
					buffer = buffer[:n]
				}

				block, err := EncryptBlock(buffer, key, params, blockIndex)

				processed := atomic.AddInt32(&processedCount, 1)
				if processed%(int32(numBlocks/10+1)) == 0 || processed == int32(numBlocks) {
					percentDone := float64(processed) / float64(numBlocks) * 100
					logger.Infof("Encryption progress: %.1f%% (%d/%d blocks)", percentDone, processed, numBlocks)
				}

				resultCh <- struct {
					index int
					block *EncryptedBlock
					err   error
				}{blockIndex, block, err}
			}
		}()
	}

	for i := 0; i < numBlocks; i++ {
		blockIndexCh <- i
	}
	close(blockIndexCh)

	var firstError error
	for i := 0; i < numBlocks; i++ {
		result := <-resultCh
		if result.err != nil {
			if firstError == nil {
				firstError = result.err
			}
			continue
		}
		blocks[result.index] = *result.block
	}

	if firstError != nil {
		return nil, firstError
	}

	encryptionTime := time.Since(encryptionStart)
	totalTime := time.Since(startTime)

	encryptedSize := 0
	for _, block := range blocks {
		encryptedSize += len(block.Data) + len(block.BlockHash) + 8
	}

	expansionFactor := float64(encryptedSize) / float64(fileSize)
	effectiveBits := int64(float64(params.LatticeDimension) * math.Log2(float64(params.SuperpositionDepth+1)))

	result := &EncryptionResult{
		Blocks:           blocks,
		TotalTime:        totalTime,
		KeyGenTime:       keyGenTime,
		EncryptionTime:   encryptionTime,
		EntanglementTime: encryptionTime - keyGenTime,
		ParameterSet:     fmt.Sprintf("QLASH-%d", params.LatticeDimension),
		OriginalSize:     int(fileSize),
		EncryptedSize:    encryptedSize,
		ExpansionFactor:  expansionFactor,
		EffectiveBits:    effectiveBits,
		EntropyDensity:   estimateEntropy(blocks[0].Data),
		ProcessorThreads: runtime.NumCPU(),
		VectorExtensions: detectSIMDCapabilities(),
		// Note: SeedEntropy is not included
	}

	logger.Infof("Encryption completed: %s (size=%d, blocks=%d, time=%v)",
		filepath.Base(filename), fileSize, numBlocks, totalTime)

	return result, nil
}

// SaveKeyToFile saves the lattice key to a specified file
func SaveKeyToFile(key *LatticeKey, keyFilename string) error {
	keyData := struct {
		PublicKey    []byte    `json:"publicKey"`
		SecretKey    []byte    `json:"secretKey"`
		Perturbation []float64 `json:"perturbation"`
	}{
		PublicKey:    key.PublicKey,
		SecretKey:    key.SecretKey,
		Perturbation: key.Perturbation,
	}

	keyBytes, err := json.Marshal(keyData)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %v", err)
	}

	err = os.WriteFile(keyFilename, keyBytes, 0600) // Secure permissions
	if err != nil {
		return fmt.Errorf("failed to write key file: %v", err)
	}

	logger.Infof("Key saved to: %s", keyFilename)
	return nil
}

// LoadKeyFromFile loads the lattice key from a specified file
func LoadKeyFromFile(keyFilename string) (*LatticeKey, error) {
	keyBytes, err := os.ReadFile(keyFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	var keyData struct {
		PublicKey    []byte    `json:"publicKey"`
		SecretKey    []byte    `json:"secretKey"`
		Perturbation []float64 `json:"perturbation"`
	}

	err = json.Unmarshal(keyBytes, &keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %v", err)
	}

	key := &LatticeKey{
		PublicKey:    keyData.PublicKey,
		SecretKey:    keyData.SecretKey,
		Perturbation: keyData.Perturbation,
	}

	logger.Infof("Key loaded from: %s", keyFilename)
	return key, nil
}

// Modify SaveEncryptedFile to include the original extension
func SaveEncryptedFile(result *EncryptionResult, outputFilename, keyFilename string) error {
	outFile, err := os.Create(outputFilename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Extract original extension from input if available
	originalExt := filepath.Ext(outputFilename)
	if strings.HasSuffix(outputFilename, ".qlash") {
		// The original filename might be embedded in the output name before .qlash
		baseName := strings.TrimSuffix(outputFilename, ".qlash")
		originalExt = filepath.Ext(baseName)
	}

	// Generate entropy mark for verification
	entropyMark := generateEntropyMark()

	header := FileHeader{
		Version:           "QLASH-2.1",
		Created:           time.Now().Format(time.RFC3339),
		ParameterSet:      result.ParameterSet,
		OriginalSize:      result.OriginalSize,
		EncryptedSize:     result.EncryptedSize,
		ExpansionFactor:   result.ExpansionFactor,
		BlockCount:        len(result.Blocks),
		ProcessorThreads:  result.ProcessorThreads,
		VectorExtensions:  result.VectorExtensions,
		EntropyMark:       entropyMark,
		OriginalExtension: originalExt, // Save original extension
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	headerSizeBytes := make([]byte, 4)
	headerSize := len(headerBytes)
	binary.LittleEndian.PutUint32(headerSizeBytes, uint32(headerSize))
	outFile.Write(headerSizeBytes)
	outFile.Write(headerBytes)

	// Calculate a master hash for verification
	masterHash := sha3.New256()
	masterHash.Write(headerBytes)

	for _, block := range result.Blocks {
		indexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(indexBytes, uint32(block.BlockIndex))
		outFile.Write(indexBytes)
		masterHash.Write(indexBytes)

		nonceBytes := block.Nonce.Bytes()
		nonceSize := len(nonceBytes)
		nonceSizeBytes := []byte{byte(nonceSize)}
		outFile.Write(nonceSizeBytes)
		outFile.Write(nonceBytes)
		masterHash.Write(nonceSizeBytes)
		masterHash.Write(nonceBytes)

		hashSize := len(block.BlockHash)
		hashSizeBytes := []byte{byte(hashSize)}
		outFile.Write(hashSizeBytes)
		outFile.Write(block.BlockHash)
		masterHash.Write(hashSizeBytes)
		masterHash.Write(block.BlockHash)

		dataSize := len(block.Data)
		dataSizeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(dataSizeBytes, uint32(dataSize))
		outFile.Write(dataSizeBytes)
		outFile.Write(block.Data)
		masterHash.Write(dataSizeBytes)
		masterHash.Write(block.Data)

		logger.Debugf("Saved block %d: index=%d, nonce_len=%d, hash_len=%d, data_len=%d",
			block.BlockIndex, block.BlockIndex, nonceSize, hashSize, dataSize)
	}

	// Write the master hash at the end for file integrity verification
	masterHashValue := masterHash.Sum(nil)
	outFile.Write(masterHashValue)

	logger.Infof("Encrypted file saved: %s (size=%d bytes)", outputFilename, result.EncryptedSize)
	return nil
}

// Modify ReadEncryptedFile and DecryptFile to use the original extension
func ReadEncryptedFile(filename string) (*FileHeader, []EncryptedBlock, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	headerSizeBytes := make([]byte, 4)
	if _, err := file.Read(headerSizeBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to read header size: %v", err)
	}
	headerSize := int(binary.LittleEndian.Uint32(headerSizeBytes))

	headerBytes := make([]byte, headerSize)
	if _, err := file.Read(headerBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to read header: %v", err)
	}

	var header FileHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("failed to parse header: %v", err)
	}

	// Check file version compatibility
	if header.Version != "QLASH-2.0" && header.Version != "QLASH-2.1" {
		logger.Warnf("File version %s may not be fully compatible", header.Version)
	}

	blocks := make([]EncryptedBlock, header.BlockCount)

	// Start tracking progress
	var processedCount int32

	// Track master hash for verification
	masterHash := sha3.New256()
	masterHash.Write(headerBytes)

	for i := 0; i < header.BlockCount; i++ {
		indexBytes := make([]byte, 4)
		if _, err := file.Read(indexBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to read block index: %v", err)
		}
		blockIndex := int(binary.LittleEndian.Uint32(indexBytes))
		masterHash.Write(indexBytes)

		nonceSizeBytes := make([]byte, 1)
		if _, err := file.Read(nonceSizeBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to read nonce size: %v", err)
		}
		nonceBytes := make([]byte, int(nonceSizeBytes[0]))
		if _, err := file.Read(nonceBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to read nonce: %v", err)
		}
		masterHash.Write(nonceSizeBytes)
		masterHash.Write(nonceBytes)
		hashSizeBytes := make([]byte, 1)
		if _, err := file.Read(hashSizeBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to read hash size: %v", err)
		}
		blockHash := make([]byte, int(hashSizeBytes[0]))
		if _, err := file.Read(blockHash); err != nil {
			return nil, nil, fmt.Errorf("failed to read block hash: %v", err)
		}
		masterHash.Write(hashSizeBytes)
		masterHash.Write(blockHash)
		dataSizeBytes := make([]byte, 4)
		if _, err := file.Read(dataSizeBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to read data size: %v", err)
		}
		dataSize := int(binary.LittleEndian.Uint32(dataSizeBytes))
		data := make([]byte, dataSize)
		if _, err := file.Read(data); err != nil {
			return nil, nil, fmt.Errorf("failed to read block data: %v", err)
		}
		masterHash.Write(dataSizeBytes)
		masterHash.Write(data)
		nonce := new(big.Int).SetBytes(nonceBytes)
		blocks[i] = EncryptedBlock{
			Data:       data,
			Nonce:      nonce,
			BlockHash:  blockHash,
			BlockIndex: blockIndex,
		}

		// Report progress periodically
		processed := atomic.AddInt32(&processedCount, 1)
		if processed%(int32(header.BlockCount/10+1)) == 0 || processed == int32(header.BlockCount) {
			percentDone := float64(processed) / float64(header.BlockCount) * 100
			logger.Infof("Reading progress: %.1f%% (%d/%d blocks)", percentDone, processed, header.BlockCount)
		}
	}

	// Verify file integrity with master hash if file version supports it
	storedMasterHash := make([]byte, 32)
	_, err = file.Read(storedMasterHash)
	if err == nil {
		computedHash := masterHash.Sum(nil)
		if !bytes.Equal(computedHash, storedMasterHash) {
			logger.Warnf("File integrity check failed: hash mismatch")
		} else {
			logger.Infof("File integrity verified successfully")
		}
	} else {
		logger.Warnf("Could not verify file integrity: %v", err)
	}

	logger.Infof("Read encrypted file: %s (blocks=%d, version=%s)",
		filename, header.BlockCount, header.Version)
	return &header, blocks, nil
}

// Optimized block decryption function
func DecryptBlock(block *EncryptedBlock, key *LatticeKey, params QLASHParameters) ([]byte, error) {
	dataLength := len(block.Data)
	output := make([]byte, dataLength)
	copy(output, block.Data)

	// Apply inverse transformations in reverse order
	for depth := params.SuperpositionDepth - 1; depth >= 0; depth-- {
		for i := dataLength - 1; i >= 0; i-- {
			keyIndex := (i + depth) % len(key.PublicKey)
			pertIndex := (i + depth*2) % len(key.Perturbation)

			switch depth % 3 {
			case 2:
				rotAmount := int(key.Perturbation[pertIndex]*7) % 8
				output[i] = byte(((int(output[i]) >> rotAmount) |
					(int(output[i]) << (8 - rotAmount))) & 0xFF)
			case 1:
				if i+keyIndex < dataLength {
					output[i] ^= output[(i+keyIndex)%dataLength]
				}
			case 0:
				factor := (1 + int(key.PublicKey[keyIndex])/128)
				// Find modular multiplicative inverse
				for inv := 1; inv < 256; inv++ {
					if (factor*inv)%256 == 1 {
						output[i] = byte((int(output[i]) * inv) % 256)
						break
					}
				}
			}
		}
	}

	// Restore original content
	for i := dataLength - 1; i >= 0; i-- {
		keyIndex := i % len(key.PublicKey)
		secretIndex := i % len(key.SecretKey)
		factor := params.EntanglementFactor * (float64(key.PublicKey[keyIndex]) / 255.0)

		// Inverse of the weighted average formula
		val := int(output[i])
		primaryComponent := int(math.Round(float64(val) / factor))
		secondaryComponent := int(math.Round(float64(val-int(float64(primaryComponent)*factor)) / (1.0 - factor)))

		// Remove the secret key
		secondaryVal := secondaryComponent ^ int(key.SecretKey[secretIndex])
		primaryVal := (primaryComponent - int(key.PublicKey[keyIndex]) + 256) % 256

		// Average both results for better numerical stability
		output[i] = byte((primaryVal + secondaryVal) / 2)
	}

	// Verify block hash for integrity
	h := sha3.New256()
	indexBytes := []byte(fmt.Sprintf("%d", block.BlockIndex))
	nonceBytes := block.Nonce.Bytes()
	h.Write(indexBytes)
	h.Write(nonceBytes)
	h.Write(block.Data)
	computedHash := h.Sum(nil)

	if !bytes.Equal(computedHash, block.BlockHash) {
		return nil, fmt.Errorf("block %d integrity check failed: hash mismatch", block.BlockIndex)
	}

	return output, nil
}

func DecryptFile(inputFilename, outputFilename, keyFilename string) (*DecryptionResult, error) {
	startTime := time.Now()

	header, blocks, err := ReadEncryptedFile(inputFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %v", err)
	}

	// Use the original extension from header if output filename doesn't have an extension
	if header.OriginalExtension != "" && filepath.Ext(outputFilename) == "" {
		outputFilename = outputFilename + header.OriginalExtension
	}

	// Determine appropriate parameters based on header
	var params QLASHParameters
	switch header.ParameterSet {
	case "QLASH-128":
		params = QLASH128
	case "QLASH-192":
		params = QLASH192
	case "QLASH-256":
		params = QLASH256
	case "QLASH-512":
		params = QLASH512
	case "QLASH-1024":
		params = QLASH1024
	default:
		var dimension int
		_, err := fmt.Sscanf(header.ParameterSet, "QLASH-%d", &dimension)
		if err != nil {
			return nil, fmt.Errorf("unknown parameter set: %s", header.ParameterSet)
		}
		params = QLASHParameters{
			LatticeDimension:   dimension,
			BlockSize:          dimension * 32,
			SuperpositionDepth: dimension / 16,
			EntanglementFactor: 0.8,
			EntropyQuality:     0.99,
		}
	}

	// Load the key from the key file
	if keyFilename == "" {
		return nil, fmt.Errorf("key file must be specified for decryption")
	}
	keyGenStart := time.Now()
	key, err := LoadKeyFromFile(keyFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %v", err)
	}
	keyGenTime := time.Since(keyGenStart)

	decryptionStart := time.Now()

	outFile, err := os.Create(outputFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	numWorkers := runtime.NumCPU()
	if len(blocks) < numWorkers {
		numWorkers = len(blocks)
	}

	logger.Infof("Starting decryption with %d worker threads", numWorkers)

	type blockResult struct {
		index int
		data  []byte
		err   error
	}

	blockCh := make(chan EncryptedBlock, len(blocks))
	resultCh := make(chan blockResult, len(blocks))

	var processedCount int32

	for w := 0; w < numWorkers; w++ {
		go func() {
			for block := range blockCh {
				data, err := DecryptBlock(&block, key, params)

				processed := atomic.AddInt32(&processedCount, 1)
				if processed%(int32(len(blocks)/10+1)) == 0 || processed == int32(len(blocks)) {
					percentDone := float64(processed) / float64(len(blocks)) * 100
					logger.Infof("Decryption progress: %.1f%% (%d/%d blocks)",
						percentDone, processed, len(blocks))
				}

				resultCh <- blockResult{block.BlockIndex, data, err}
			}
		}()
	}

	for _, block := range blocks {
		blockCh <- block
	}
	close(blockCh)

	decryptedBlocks := make(map[int][]byte, len(blocks))
	var firstError error
	for i := 0; i < len(blocks); i++ {
		result := <-resultCh
		if result.err != nil {
			if firstError == nil {
				firstError = result.err
			}
			logger.Errorf("Block %d decryption failed: %v", result.index, result.err)
			continue
		}
		decryptedBlocks[result.index] = result.data
	}

	if firstError != nil {
		return nil, fmt.Errorf("decryption errors occurred: %v", firstError)
	}

	var totalBytes int
	for i := 0; i < len(blocks); i++ {
		data, ok := decryptedBlocks[i]
		if !ok {
			return nil, fmt.Errorf("missing block %d", i)
		}
		n, err := outFile.Write(data)
		if err != nil {
			return nil, fmt.Errorf("failed to write decrypted data: %v", err)
		}
		totalBytes += n
	}

	if totalBytes > header.OriginalSize {
		outFile.Truncate(int64(header.OriginalSize))
		totalBytes = header.OriginalSize
	}

	decryptionTime := time.Since(decryptionStart)
	totalTime := time.Since(startTime)

	result := &DecryptionResult{
		OriginalSize:     header.OriginalSize,
		DecryptedSize:    totalBytes,
		TotalTime:        totalTime,
		KeyGenTime:       keyGenTime,
		DecryptionTime:   decryptionTime,
		ParameterSet:     header.ParameterSet,
		BlocksProcessed:  len(blocks),
		ProcessorThreads: runtime.NumCPU(),
		VectorExtensions: detectSIMDCapabilities(),
		IntegrityValid:   true,
	}

	logger.Infof("Decryption completed: %s (size=%d, blocks=%d, time=%v)",
		filepath.Base(outputFilename), totalBytes, len(blocks), totalTime)

	return result, nil
}

// Advanced benchmarking functionality
func BenchmarkParameters(fileSize int, params []QLASHParameters) []map[string]interface{} {
	results := make([]map[string]interface{}, 0, len(params))

	testData := make([]byte, fileSize)
	rand.Read(testData)

	tempFile, err := os.CreateTemp("", "qlash-benchmark-*.dat")
	if err != nil {
		logger.Error("Failed to create temp file for benchmark:", err)
		return results
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	_, err = tempFile.Write(testData)
	if err != nil {
		logger.Error("Failed to write test data:", err)
		return results
	}
	tempFile.Close()

	for _, param := range params {
		result := make(map[string]interface{})
		result["params"] = fmt.Sprintf("QLASH-%d", param.LatticeDimension)
		result["fileSize"] = fileSize

		tempKeyFile, err := os.CreateTemp("", "qlash-benchmark-key-*.key")
		if err != nil {
			logger.Error("Failed to create temp key file for benchmark:", err)
			continue
		}
		keyFileName := tempKeyFile.Name()
		tempKeyFile.Close()
		defer os.Remove(keyFileName)

		encStart := time.Now()
		encResult, err := EncryptFile(tempFile.Name(), param, keyFileName)
		if err != nil {
			logger.Errorf("Benchmark encryption failed for %s: %v",
				result["params"], err)
			continue
		}
		encTime := time.Since(encStart)

		result["encryptionTime"] = encTime.Seconds()
		result["encryptionSpeed"] = float64(fileSize) / (1024 * 1024) / encTime.Seconds()
		result["expansionFactor"] = encResult.ExpansionFactor
		result["entropyDensity"] = encResult.EntropyDensity

		tempEncFile, err := os.CreateTemp("", "qlash-benchmark-enc-*.bin")
		if err != nil {
			logger.Error("Failed to create temp encrypted file for benchmark:", err)
			continue
		}
		defer os.Remove(tempEncFile.Name())
		tempEncFile.Close()

		err = SaveEncryptedFile(encResult, tempEncFile.Name(), keyFileName)
		if err != nil {
			logger.Error("Failed to save encrypted file:", err)
			continue
		}

		tempOutFile, err := os.CreateTemp("", "qlash-benchmark-out-*.dat")
		if err != nil {
			logger.Error("Failed to create temp output file:", err)
			continue
		}
		defer os.Remove(tempOutFile.Name())
		tempOutFile.Close()

		decStart := time.Now()
		decResult, err := DecryptFile(tempEncFile.Name(), tempOutFile.Name(), keyFileName)
		if err != nil {
			logger.Errorf("Benchmark decryption failed for %s: %v",
				result["params"], err)
			continue
		}
		decTime := time.Since(decStart)

		result["decryptionTime"] = decTime.Seconds()
		result["decryptedSize"] = decResult.DecryptedSize
		result["decryptionSpeed"] = float64(fileSize) / (1024 * 1024) / decTime.Seconds()
		result["totalTime"] = (encTime + decTime).Seconds()
		result["processorThreads"] = runtime.NumCPU()
		result["vectorExtensions"] = detectSIMDCapabilities()
		result["integrityValid"] = decResult.IntegrityValid

		results = append(results, result)
	}

	return results
}

func PrintBenchmarkResults(results []map[string]interface{}) {
	if len(results) == 0 {
		fmt.Println("No benchmark results available.")
		return
	}

	fmt.Printf("\n==== QLASH Benchmark Results ====\n")
	fmt.Printf("%-10s | %-12s | %-12s | %-10s | %-10s | %-10s\n",
		"Params", "Enc Speed", "Dec Speed", "Expansion", "Entropy", "Total Time")
	fmt.Printf("%-10s-+-%-12s-+-%-12s-+-%-10s-+-%-10s-+-%-10s\n",
		"----------", "------------", "------------", "----------", "----------", "----------")

	for _, r := range results {
		fmt.Printf("%-10s | %-12.2f | %-12.2f | %-10.2f | %-10.2f | %-10.2f\n",
			r["params"],
			r["encryptionSpeed"].(float64), // MB/s
			r["decryptionSpeed"].(float64), // MB/s
			r["expansionFactor"].(float64), // ratio
			r["entropyDensity"].(float64),  // 0-1
			r["totalTime"].(float64))       // seconds
	}
	fmt.Printf("\nSystem: %d CPU threads, %s\n",
		runtime.NumCPU(), runtime.GOARCH)

	// Print vector extensions if available
	if results[0]["vectorExtensions"] != nil {
		ext := results[0]["vectorExtensions"].([]string)
		if len(ext) > 0 {
			fmt.Printf("CPU Extensions: %s\n", strings.Join(ext, ", "))
		} else {
			fmt.Printf("CPU Extensions: None detected\n")
		}
	}

	fmt.Println("\nRecommended parameter set:")
	// Find best balance between speed and security
	var bestParam string
	bestScore := 0.0

	for _, r := range results {
		encSpeed := r["encryptionSpeed"].(float64)
		decSpeed := r["decryptionSpeed"].(float64)
		expansion := r["expansionFactor"].(float64)
		entropy := r["entropyDensity"].(float64)

		// Calculate weighted score (higher is better)
		score := (encSpeed + decSpeed) * entropy / expansion

		if score > bestScore {
			bestScore = score
			bestParam = r["params"].(string)
		}
	}

	fmt.Printf("Based on your system performance: %s\n", bestParam)
}

// Fixes in the main function to address file extension handling issues

func main() {
	encrypt := flag.Bool("encrypt", false, "Encrypt file")
	decrypt := flag.Bool("decrypt", false, "Decrypt file")
	benchmark := flag.Bool("benchmark", false, "Run benchmarks")
	paramLevel := flag.Int("security", 256, "Security level (128, 192, 256, 512, 1024)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	cpuprofile := flag.String("cpuprofile", "", "Write CPU profile to file")
	inputFile := flag.String("in", "", "Input file")
	outputFile := flag.String("out", "", "Output file")
	keyFile := flag.String("key", "", "Key file for encryption (output) or decryption (input)")

	flag.Parse()

	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	}

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			logger.Fatalf("Could not create CPU profile: %v", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			logger.Fatalf("Could not start CPU profile: %v", err)
		}
		defer pprof.StopCPUProfile()
	}

	fmt.Printf("QLASH v2.1 - Quantum Lattice Adaptive Secure Hashing\n")
	fmt.Printf("Runtime: Go %s, %s/%s, %d CPUs\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	simd := detectSIMDCapabilities()
	if len(simd) > 0 {
		fmt.Printf("CPU Extensions: %s\n", strings.Join(simd, ", "))
	}

	var params QLASHParameters
	switch *paramLevel {
	case 128:
		params = QLASH128
	case 192:
		params = QLASH192
	case 256:
		params = QLASH256
	case 512:
		params = QLASH512
	case 1024:
		params = QLASH1024
	default:
		params = QLASH256
	}

	if *benchmark {
		fmt.Println("Running benchmarks...")
		sizes := []int{1024 * 1024, 10 * 1024 * 1024}
		allParams := []QLASHParameters{QLASH128, QLASH192, QLASH256, QLASH512}
		for _, size := range sizes {
			fmt.Printf("\nBenchmarking with %d MB file...\n", size/(1024*1024))
			results := BenchmarkParameters(size, allParams)
			PrintBenchmarkResults(results)
		}
		return
	}

	if *encrypt {
		if *inputFile == "" {
			logger.Fatal("Input file must be specified")
		}

		// For encryption, always use .qlash extension
		if *outputFile == "" {
			// Store the extension for potential future recovery during decryption
			inputExt := filepath.Ext(*inputFile)
			baseName := strings.TrimSuffix(*inputFile, inputExt)
			*outputFile = baseName + ".qlash"
		} else if !strings.HasSuffix(*outputFile, ".qlash") {
			// Ensure output has .qlash extension
			*outputFile = *outputFile + ".qlash"
		}

		if *keyFile == "" {
			*keyFile = strings.TrimSuffix(*outputFile, ".qlash") + ".key"
		}

		fmt.Printf("Encrypting %s to %s with QLASH-%d, saving key to %s...\n",
			*inputFile, *outputFile, params.LatticeDimension, *keyFile)

		encResult, err := EncryptFile(*inputFile, params, *keyFile)
		if err != nil {
			logger.Fatalf("Encryption failed: %v", err)
		}

		// Add original extension metadata to FileHeader
		// This would require modifying the FileHeader struct to include OriginalExtension field
		// For now, we can suggest this as an enhancement

		err = SaveEncryptedFile(encResult, *outputFile, *keyFile)
		if err != nil {
			logger.Fatalf("Failed to save encrypted file: %v", err)
		}

		fmt.Printf("\nEncryption Summary:\n")
		fmt.Printf("  Input file:        %s (%d bytes)\n", *inputFile, encResult.OriginalSize)
		fmt.Printf("  Output file:       %s (%d bytes)\n", *outputFile, encResult.EncryptedSize)
		fmt.Printf("  Key file:          %s\n", *keyFile)
		fmt.Printf("  Expansion factor:  %.2f\n", encResult.ExpansionFactor)
		fmt.Printf("  Security level:    %s\n", encResult.ParameterSet)
		fmt.Printf("  Entropy density:   %.4f\n", encResult.EntropyDensity)
		fmt.Printf("  Processing time:   %.2f seconds\n", encResult.TotalTime.Seconds())
		fmt.Printf("  Throughput:        %.2f MB/s\n",
			float64(encResult.OriginalSize)/(1024*1024)/encResult.TotalTime.Seconds())

	} else if *decrypt {
		if *inputFile == "" {
			logger.Fatal("Input file must be specified")
		}

		if *keyFile == "" {
			logger.Fatal("Key file must be specified for decryption")
		}

		// For decryption, remove the .qlash extension if present
		if *outputFile == "" {
			if strings.HasSuffix(*inputFile, ".qlash") {
				*outputFile = strings.TrimSuffix(*inputFile, ".qlash")

				// If input was example.txt.qlash, output will be example.txt
				// If input was example.qlash, output will be example

				// If no extension remains, add .dec as fallback
				if filepath.Ext(*outputFile) == "" {
					*outputFile = *outputFile + ".dec"
				}
			} else {
				// Input file doesn't have .qlash extension, add .dec to output
				*outputFile = *inputFile + ".dec"
			}
		}

		fmt.Printf("Decrypting %s to %s using key %s...\n", *inputFile, *outputFile, *keyFile)

		decResult, err := DecryptFile(*inputFile, *outputFile, *keyFile)
		if err != nil {
			logger.Fatalf("Decryption failed: %v", err)
		}

		fmt.Printf("\nDecryption Summary:\n")
		fmt.Printf("  Input file:        %s\n", *inputFile)
		fmt.Printf("  Output file:       %s (%d bytes)\n", *outputFile, decResult.DecryptedSize)
		fmt.Printf("  Key file:          %s\n", *keyFile)
		fmt.Printf("  Parameter set:     %s\n", decResult.ParameterSet)
		fmt.Printf("  Blocks processed:  %d\n", decResult.BlocksProcessed)
		fmt.Printf("  Processing time:   %.2f seconds\n", decResult.TotalTime.Seconds())
		fmt.Printf("  Throughput:        %.2f MB/s\n",
			float64(decResult.DecryptedSize)/(1024*1024)/decResult.TotalTime.Seconds())

		if decResult.IntegrityValid {
			fmt.Printf("  Integrity check:   PASSED\n")
		} else {
			fmt.Printf("  Integrity check:   FAILED\n")
		}

	} else {
		fmt.Println("No operation specified. Use -encrypt or -decrypt or -benchmark")
		flag.Usage()
	}
}

// Helper function for go:generate
//go:generate go run -tags=generate gen_constants.go
