package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	writeToFile *bool
	tempDir     *string
)

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

	log.Printf("[%d] Complete: %d chunks, %d total bytes", timestamp, chunkCount, totalBytes)

	savedTo := ""
	if *writeToFile {
		savedTo = fmt.Sprintf("%s/%d-chunk-*.mp4 (%d files)", *tempDir, timestamp, chunkCount)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":          "success",
		"chunks_received": chunkCount,
		"bytes_received":  totalBytes,
		"saved_to":        savedTo,
	})
}

func main() {
	port := flag.Int("port", 8889, "HTTP port")
	writeToFile = flag.Bool("write_to_file", false, "write each chunk as a separate file")
	tempDir = flag.String("temp_dir", "../temp", "directory to write chunk files")
	flag.Parse()

	os.MkdirAll(*tempDir, 0755)

	addr := fmt.Sprintf(":%d", *port)
	http.HandleFunc("/stream-upload", handleStreamUpload)
	log.Printf("Streaming backend listening on %s, temp_dir=%s", addr, *tempDir)
	log.Fatal(http.ListenAndServe(addr, nil))
}
