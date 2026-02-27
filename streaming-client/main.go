package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func findFirstMP4(dir string) string {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.mp4"))
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func main() {
	defaultFile := findFirstMP4("../resources/")
	fileFlag := flag.String("file", defaultFile, "path to video file to upload")
	urlFlag := flag.String("url", "http://localhost:18081/stream-upload", "target URL")
	clientTempDir := flag.String("client_temp_dir", "../temp-client", "directory to save response chunks")
	flag.Parse()

	if *fileFlag == "" {
		log.Fatal("No file specified and no .mp4 found in ../resources/")
	}

	os.MkdirAll(*clientTempDir, 0755)

	f, err := os.Open(*fileFlag)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	client := &http.Client{
		Timeout: 600 * time.Second,
	}

	req, err := http.NewRequest("POST", *urlFlag, f)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	// ContentLength = -1 forces chunked transfer encoding
	req.ContentLength = -1
	req.Header.Set("Content-Type", "video/mp4")
	req.Header.Set("X-Streaming", "true")

	log.Printf("Uploading %s → %s", *fileFlag, *urlFlag)
	start := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Response Content-Type: %s\n", resp.Header.Get("Content-Type"))

	// Read response in 64KB chunks and save each as its own file
	buffer := make([]byte, 64*1024)
	chunkCount := 0
	var totalBytes int64
	timestamp := time.Now().UnixNano()

	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			chunkCount++
			totalBytes += int64(n)
			chunkFile := fmt.Sprintf("%s/%d-resp-chunk-%04d.mp4", *clientTempDir, timestamp, chunkCount)
			if werr := os.WriteFile(chunkFile, buffer[:n], 0644); werr != nil {
				log.Printf("Failed to write response chunk %d: %v", chunkCount, werr)
			} else {
				fmt.Printf("← Chunk #%04d: %6d bytes  →  %s\n", chunkCount, n, chunkFile)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Error reading response: %v", err)
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("\nDone: %d response chunks, %d bytes, elapsed: %s\n", chunkCount, totalBytes, elapsed)
	fmt.Printf("Chunks saved to: %s/\n\n", *clientTempDir)
	fmt.Printf("▶  Play assembled response:\n")
	fmt.Printf("   cat %s/%d-resp-chunk-*.mp4 > /tmp/response.mp4 && open /tmp/response.mp4\n\n", *clientTempDir, timestamp)
	fmt.Printf("▶  Play individual chunk (e.g. chunk 5):\n")
	fmt.Printf("   ffplay %s/%d-resp-chunk-0005.mp4\n", *clientTempDir, timestamp)
}
