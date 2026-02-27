package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	writeToFile   *bool
	tempDir       *string
	responseVideo *string
)

func findFirstMP4(dir string) string {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.mp4"))
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func handleStreamUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	timestamp := time.Now().UnixNano()

	log.Printf("[%d] Received %s %s", timestamp, r.Method, r.RequestURI)
	for name, values := range r.Header {
		for _, value := range values {
			log.Printf("[%d] header: %s: %s", timestamp, name, value)
		}
	}

	// --- receive request body chunks ---
	buffer := make([]byte, 64*1024)
	var totalBytes int64
	chunkCount := 0

	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			chunkCount++
			totalBytes += int64(n)
			log.Printf("[%d] Chunk #%d: %d bytes, total %d bytes", timestamp, chunkCount, n, totalBytes)
			if *writeToFile {
				chunkFile := fmt.Sprintf("%s/%d-chunk-%04d.mp4", *tempDir, timestamp, chunkCount)
				if werr := os.WriteFile(chunkFile, buffer[:n], 0644); werr != nil {
					log.Printf("[%d] Failed to write chunk %d: %v", timestamp, chunkCount, werr)
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[%d] Error reading body: %v", timestamp, err)
			http.Error(w, "Error reading body", http.StatusInternalServerError)
			return
		}
	}

	log.Printf("[%d] Upload complete: %d chunks, %d total bytes", timestamp, chunkCount, totalBytes)

	// --- stream video response ---
	videoPath := *responseVideo
	if videoPath == "" {
		videoPath = findFirstMP4("../resources/")
	}

	vf, err := os.Open(videoPath)
	if err != nil {
		// No video available — fall back to JSON
		log.Printf("[%d] No response video found (%v), returning JSON", timestamp, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "success",
			"chunks_received": chunkCount,
			"bytes_received":  totalBytes,
		})
		return
	}
	defer vf.Close()

	fi, _ := vf.Stat()
	log.Printf("[%d] Streaming response: %s (%d bytes)", timestamp, videoPath, fi.Size())

	// No Content-Length → Go HTTP uses chunked transfer encoding automatically
	w.Header().Set("Content-Type", "video/mp4")

	flusher, canFlush := w.(http.Flusher)
	respBuf := make([]byte, 64*1024)
	respChunk := 0

	for {
		n, err := vf.Read(respBuf)
		if n > 0 {
			respChunk++
			w.Write(respBuf[:n])
			if canFlush {
				flusher.Flush() // push each chunk immediately without waiting for EOF
			}
			log.Printf("[%d] Response chunk #%d: %d bytes", timestamp, respChunk, n)
		}
		if err != nil {
			break
		}
	}

	log.Printf("[%d] Response complete: %d chunks sent", timestamp, respChunk)
}

func main() {
	port := flag.Int("port", 8889, "HTTP port")
	writeToFile = flag.Bool("write_to_file", false, "write each request chunk as a separate file")
	tempDir = flag.String("temp_dir", "../temp", "directory to write request chunk files")
	responseVideo = flag.String("response_video", "", "video file to stream as response (default: first *.mp4 in ../resources/)")
	flag.Parse()

	os.MkdirAll(*tempDir, 0755)

	addr := fmt.Sprintf(":%d", *port)
	http.HandleFunc("/stream-upload", handleStreamUpload)
	log.Printf("Streaming backend listening on %s, temp_dir=%s", addr, *tempDir)
	log.Fatal(http.ListenAndServe(addr, nil))
}
