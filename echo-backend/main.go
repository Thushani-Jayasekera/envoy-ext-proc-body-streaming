package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
)

// echoHandler streams the request body back as the response body in real time.
// Each read from the request is immediately flushed to the response, enabling
// true full-duplex streaming when used with Envoy ext_proc FULL_DUPLEX_STREAMED.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	flusher, canFlush := w.(http.Flusher)

	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	// Do not set Content-Length — forces chunked transfer encoding so the
	// response can start before the request body is fully received.
	w.WriteHeader(http.StatusOK)

	buf := make([]byte, 32*1024)
	for {
		n, readErr := r.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return
		}
	}
}

func main() {
	port := flag.Int("port", 8688, "HTTP port")
	flag.Parse()

	http.HandleFunc("/", echoHandler)
	addr := fmt.Sprintf(":%d", *port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		panic(err)
	}
}
