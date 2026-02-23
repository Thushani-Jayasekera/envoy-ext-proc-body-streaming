package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"

	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

var _ ext_proc_v3.ExternalProcessorServer = &server{}

type server struct {
}

// isGzipData checks if the data starts with gzip magic bytes
func isGzipData(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// decodeBody decodes the body based on the content encoding
func decodeBody(body []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		// In streaming mode, we receive partial chunks that may not be complete gzip streams
		// Try to decompress only if we have gzip magic bytes
		if !isGzipData(body) {
			// Check if body looks like compressed data (non-printable bytes)
			if hasNonPrintableBytes(body) {
				log.Warn().Msgf("Body appears compressed but doesn't have gzip header (partial chunk in stream). First bytes: %v", body[:min(10, len(body))])
			} else {
				log.Info().Msg("Body is already decompressed (readable text)")
			}
			return body, nil
		}

		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer reader.Close()

		decoded, err := io.ReadAll(reader)
		if err != nil {
			return body, fmt.Errorf("failed to read gzip data: %w", err)
		}
		log.Info().Msg("Successfully decompressed gzip body")
		return decoded, nil
	case "":
		// No encoding, return as is
		return body, nil
	default:
		// Unknown encoding, return as is and log
		log.Warn().Msgf("Unknown content encoding: %s", encoding)
		return body, nil
	}
}

// hasNonPrintableBytes checks if data contains mostly non-printable bytes (likely compressed)
func hasNonPrintableBytes(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	nonPrintable := 0
	checkLen := min(100, len(data))
	for i := 0; i < checkLen; i++ {
		b := data[i]
		// Check for non-printable ASCII (excluding whitespace)
		if (b < 32 && b != 9 && b != 10 && b != 13) || b > 126 {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(checkLen) > 0.3
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ChatCompletionChunk represents a streaming chunk from OpenAI
type ChatCompletionChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Content string `json:"content,omitempty"`
			Role    string `json:"role,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

// parseSSETokens parses SSE format and extracts tokens from delta.content
func parseSSETokens(body string) []string {
	var tokens []string

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines
		if line == "" {
			continue
		}

		// Check for data prefix
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		// Extract the JSON part
		data := strings.TrimPrefix(line, "data: ")

		// Check for stream end
		if data == "[DONE]" {
			break
		}

		// Parse JSON
		var chunk ChatCompletionChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			// Log and continue, don't fail on parse errors
			log.Warn().Err(err).Msg("Failed to parse SSE chunk")
			continue
		}

		// Extract content from delta
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			tokens = append(tokens, chunk.Choices[0].Delta.Content)
		}
	}

	return tokens
}

// Process implements ext_procv3.ExternalProcessorServer.
func (s *server) Process(processServer ext_proc_v3.ExternalProcessor_ProcessServer) error {
	ctx := processServer.Context()
	rnd := rand.Int()
	var contentEncoding string       // Track content encoding for this request
	var gzipReader *gzip.Reader      // Persistent gzip reader for streaming decompression
	var pipeReader *io.PipeReader    // Pipe reader for streaming
	var pipeWriter *io.PipeWriter    // Pipe writer for streaming
	var decompressChan chan []byte   // Channel to receive decompressed data

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, err := processServer.Recv()
		if err == io.EOF {
			log.Info().Msg("EOF ******************************************")
			return nil
		}
		if err != nil {
			// log.Error().Err(err).Msg("Error receiving stream request")
			// return status.Errorf(codes.Unknown, "cannot receive stream request: %v", err)
			log.Info().Err(err).Msg("Stream completed")
			return nil
		}

		log.Info().Msgf("Processing Request : %d", rnd)
		time.Sleep(1 * time.Millisecond)
		// route_name := req.MetadataContext.FilterMetadata["envoy.filters.http.ext_proc"].Fields["meta.route_name"].GetStringValue()

		switch value := req.Request.(type) {

		case *pb.ProcessingRequest_RequestHeaders:
			log.Info().Msgf("******** Processing Request Headers ********* %v", rnd)
			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_RequestHeaders{},
				ModeOverride: &ext_procv3.ProcessingMode{
					RequestTrailerMode:  ext_procv3.ProcessingMode_SKIP,
					RequestBodyMode:     ext_procv3.ProcessingMode_FULL_DUPLEX_STREAMED,
					ResponseHeaderMode:  ext_procv3.ProcessingMode_SEND,
					ResponseBodyMode:    ext_procv3.ProcessingMode_FULL_DUPLEX_STREAMED,
					ResponseTrailerMode: ext_procv3.ProcessingMode_SKIP,
				},
			}

			if err := processServer.Send(resp); err != nil {
				log.Error().Err(err).Msg("Error sending response")
			}

		case *pb.ProcessingRequest_RequestBody:
			log.Info().Msgf("******** Processing Request Body ********* %v", rnd)
			body := value.RequestBody.Body

			log.Info().Msgf("Received request body: " + string(body))

			if value.RequestBody.EndOfStream {
				log.Info().Msg("Request Body EOF ****************************************************************************************")
			}

			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_RequestBody{
					RequestBody: &pb.BodyResponse{
						Response: &pb.CommonResponse{
							BodyMutation: &pb.BodyMutation{
								Mutation: &pb.BodyMutation_StreamedResponse{
									StreamedResponse: &pb.StreamedBodyResponse{
										Body:        body,
										EndOfStream: value.RequestBody.EndOfStream,
									},
								},
							},
						},
					},
				},
			}

			if err := processServer.Send(resp); err != nil {
				log.Error().Err(err).Msg("Error sending response")
			}

		case *pb.ProcessingRequest_ResponseHeaders:
			log.Info().Msgf("******** Processing Response Headers ********* %v", rnd)

			// Capture Content-Encoding header
			for _, header := range value.ResponseHeaders.Headers.Headers {
				if strings.ToLower(header.Key) == "content-encoding" {
					contentEncoding = string(header.RawValue)
					log.Info().Msgf("Detected Content-Encoding: %s", contentEncoding)
					break
				}
			}

			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseHeaders{},
				// Don't override mode, use what's configured in envoy.yaml
			}

			if err := processServer.Send(resp); err != nil {
				log.Error().Err(err).Msg("Error sending response")
			}

		case *pb.ProcessingRequest_ResponseBody:
			log.Info().Msgf("******** Processing Response Body ********* %v", rnd)

			body := value.ResponseBody.Body
			log.Info().Msgf("Received chunk: %d bytes, EndOfStream: %v", len(body), value.ResponseBody.EndOfStream)

			var decodedBody []byte

			if contentEncoding == "gzip" {
				// Initialize pipe and gzip reader on first chunk
				if pipeReader == nil {
					pipeReader, pipeWriter = io.Pipe()
					decompressChan = make(chan []byte, 10)

					// Start goroutine to decompress data from pipe
					go func() {
						defer close(decompressChan)
						var err error
						gzipReader, err = gzip.NewReader(pipeReader)
						if err != nil {
							log.Error().Err(err).Msg("Failed to create gzip reader")
							return
						}
						defer gzipReader.Close()

						log.Info().Msg("Initialized streaming gzip reader")

						// Continuously read decompressed data
						buf := make([]byte, 4096)
						for {
							n, err := gzipReader.Read(buf)
							if n > 0 {
								// Send decompressed data to channel
								data := make([]byte, n)
								copy(data, buf[:n])
								decompressChan <- data
							}
							if err != nil {
								if err != io.EOF {
									log.Warn().Err(err).Msg("Error reading from gzip stream")
								}
								break
							}
						}
					}()
				}

				// Write compressed chunk to pipe
				_, err := pipeWriter.Write(body)
				if err != nil {
					log.Error().Err(err).Msg("Failed to write to pipe")
				}

				// Close pipe writer on end of stream
				if value.ResponseBody.EndOfStream {
					pipeWriter.Close()
					log.Info().Msg("Closed pipe writer")
				}

				// Read all available decompressed data from channel (non-blocking)
				var allDecompressed bytes.Buffer
			readLoop:
				for {
					select {
					case data, ok := <-decompressChan:
						if !ok {
							break readLoop
						}
						allDecompressed.Write(data)
					default:
						// No more data available right now
						break readLoop
					}
				}

				decodedBody = allDecompressed.Bytes()
				if len(decodedBody) > 0 {
					log.Info().Msgf("Decompressed: %d bytes", len(decodedBody))
				}
			} else {
				// No compression, use body as-is
				decodedBody = body
			}

			// Print decompressed SSE events as they arrive
			if len(decodedBody) > 0 {
				fmt.Println("=== SSE Event Chunk ===")
				fmt.Println(string(decodedBody))
				fmt.Println("=======================")

				// Parse SSE format and extract tokens (for OpenAI)
				tokens := parseSSETokens(string(decodedBody))
				if len(tokens) > 0 {
					fmt.Println("=== Tokens ===")
					for _, token := range tokens {
						fmt.Printf("Token: %s\n", token)
					}
					fmt.Println("==============")
				}
			}

			if value.ResponseBody.EndOfStream {
				log.Info().Msg("Response Body EOF ****************************************************************************************")
			}

			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseBody{
					ResponseBody: &pb.BodyResponse{
						Response: &pb.CommonResponse{
							BodyMutation: &pb.BodyMutation{
								Mutation: &pb.BodyMutation_StreamedResponse{
									StreamedResponse: &pb.StreamedBodyResponse{
										Body:        body,
										EndOfStream: value.ResponseBody.EndOfStream,
									},
								},
							},
						},
					},
				},
			}

			if err := processServer.Send(resp); err != nil {
				log.Error().Err(err).Msg("Error sending response")
			}

		default:
			log.Warn().Msgf("Unknown request type: %T", value)
		}
	}
}

func main() {
	port := flag.Int("port", 9001, "gRPC port")
	flag.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to listen: %v", err)
	}

	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(1024*1024*50), // 50 MB
		grpc.MaxSendMsgSize(1024*1024*50), // 50 MB
	)
	ext_proc_v3.RegisterExternalProcessorServer(gs, &server{})
	log.Info().Msgf("gRPC server listening on port %d", *port)
	gs.Serve(lis)
}
