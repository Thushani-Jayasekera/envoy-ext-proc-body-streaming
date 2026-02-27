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
	matches, err := filepath.Glob(filepath.Join(dir, "*.mp4"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func main() {
	defaultFile := findFirstMP4("../resources/")
	fileFlag := flag.String("file", defaultFile, "path to video file to upload")
	urlFlag := flag.String("url", "http://localhost:18081/stream-upload", "target URL")
	flag.Parse()

	if *fileFlag == "" {
		log.Fatal("No file specified and no .mp4 found in ../resources/")
	}

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
	// Setting ContentLength = -1 forces Go's HTTP client to use chunked transfer encoding,
	// which causes transfer-encoding: chunked to appear in request headers.
	req.ContentLength = -1
	req.Header.Set("Content-Type", "video/mp4")
	req.Header.Set("X-Streaming", "true")

	log.Printf("Uploading %s to %s", *fileFlag, *urlFlag)
	start := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)
	body, _ := io.ReadAll(resp.Body)

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Response: %s\n", string(body))
	fmt.Printf("Elapsed: %s\n", elapsed)
}
