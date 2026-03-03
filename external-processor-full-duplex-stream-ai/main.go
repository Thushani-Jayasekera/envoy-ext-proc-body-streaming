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
	"regexp"
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

// truncate returns s truncated to at most max runes, with "..." if truncated.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}

// ── PII Masking ───────────────────────────────────────────────────────────────

// piiPattern holds a compiled regex and its replacement string.
type piiPattern struct {
	name        string
	re          *regexp.Regexp
	replacement string
}

// piiPatterns is the list of PII patterns applied to every body.
// Patterns are applied in order — earlier patterns take priority.
var piiPatterns = []piiPattern{
	{
		name:        "SSN",
		re:          regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		replacement: "***-**-****",
	},
	{
		name:        "CreditCard",
		re:          regexp.MustCompile(`\b(?:\d{4}[\s\-]?){3}\d{4}\b`),
		replacement: "****-****-****-****",
	},
	{
		name:        "Email",
		re:          regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
		replacement: "[REDACTED-EMAIL]",
	},
	{
		name:        "Phone",
		re:          regexp.MustCompile(`\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b`),
		replacement: "[REDACTED-PHONE]",
	},
}

// maskPII applies all PII patterns to data and returns the masked result.
// It also logs each match found so it is visible in the ext-proc output.
func maskPII(data []byte, requestID int) []byte {
	log.Debug().
		Int("input_bytes", len(data)).
		Str("input_preview", truncate(string(data), 200)).
		Msgf("[PII-MASK] scanning [%d]", requestID)

	result := data
	for _, p := range piiPatterns {
		matches := p.re.FindAll(result, -1)
		if len(matches) > 0 {
			log.Warn().
				Str("pii_type", p.name).
				Int("matches_found", len(matches)).
				Msgf("[PII-MASK] masking %d %s match(es) [%d]", len(matches), p.name, requestID)
			result = p.re.ReplaceAll(result, []byte(p.replacement))
		}
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────

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
	var contentEncoding string     // Track content encoding for this request
	var gzipReader *gzip.Reader    // Persistent gzip reader for streaming decompression
	var pipeReader *io.PipeReader  // Pipe reader for streaming
	var pipeWriter *io.PipeWriter  // Pipe writer for streaming
	var decompressChan chan []byte // Channel to receive decompressed data
	var isStreaming bool           // True if response is chunked/SSE, false if Content-Length (buffered)
	// Token monitoring for OpenAI-style streaming response
	var responseChunkIndex int
	var totalTokensReceived int
	var allTokensCollected []string
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
					ResponseBodyMode:    ext_procv3.ProcessingMode_BUFFERED,
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
			log.Info().Msgf("======== RESPONSE HEADERS [%d] ========", rnd)

			// Dump all response headers and capture relevant ones
			var transferEncoding string
			var contentType string
			var contentLength string
			for _, header := range value.ResponseHeaders.Headers.Headers {
				log.Info().Msgf("  [RES-HDR] %s: %s", header.Key, string(header.RawValue))
				switch strings.ToLower(header.Key) {
				case "content-encoding":
					contentEncoding = string(header.RawValue)
				case "transfer-encoding":
					transferEncoding = string(header.RawValue)
				case "content-type":
					contentType = string(header.RawValue)
				case "content-length":
					contentLength = string(header.RawValue)
				}
			}

			// Detect whether the response is truly streaming:
			//   Transfer-Encoding: chunked → streaming (size unknown, arrives in chunks)
			//   Content-Type: text/event-stream → SSE streaming
			//   Content-Length present → non-streaming (complete response, size known)
			isChunked := strings.Contains(strings.ToLower(transferEncoding), "chunked")
			isSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream")
			isStreaming = isChunked || isSSE

			modeLabel := "FULL_DUPLEX_STREAMED (no override)"
			if !isStreaming {
				modeLabel = "BUFFERED (override)"
			}
			log.Info().
				Str("transfer-encoding", transferEncoding).
				Str("content-type", contentType).
				Str("content-length", contentLength).
				Str("content-encoding", contentEncoding).
				Bool("is_chunked", isChunked).
				Bool("is_sse", isSSE).
				Bool("is_streaming", isStreaming).
				Str("mode_decision", modeLabel).
				Msgf("[STREAM-DETECT] request=%d", rnd)

			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseHeaders{},
			}

			if !isStreaming {
				// Non-streaming response (Content-Length present, no chunked encoding).
				// Override to BUFFERED so Envoy buffers the complete body before sending
				// to ext-proc. This preserves Content-Length on the response to the client
				// and avoids converting to Transfer-Encoding: chunked, which breaks clients
				// that do not support chunked responses.
				log.Warn().Msgf("[MODE-OVERRIDE] Non-streaming response — overriding response body mode to BUFFERED [%d]", rnd)
				resp.ModeOverride = &ext_procv3.ProcessingMode{
					RequestTrailerMode:  ext_procv3.ProcessingMode_SKIP,
					RequestBodyMode:     ext_procv3.ProcessingMode_BUFFERED,
					ResponseHeaderMode:  ext_procv3.ProcessingMode_SEND,
					ResponseBodyMode:    ext_procv3.ProcessingMode_BUFFERED,
					ResponseTrailerMode: ext_procv3.ProcessingMode_SKIP,
				}
			} else {
				log.Warn().Msgf("[MODE-OVERRIDE] Streaming response — overriding response body mode to FULL_DUPLEX_STREAMED [%d]", rnd)
				resp.ModeOverride = &ext_procv3.ProcessingMode{
					RequestTrailerMode:  ext_procv3.ProcessingMode_SKIP,
					RequestBodyMode:     ext_procv3.ProcessingMode_BUFFERED,
					ResponseHeaderMode:  ext_procv3.ProcessingMode_SEND,
					ResponseBodyMode:    ext_procv3.ProcessingMode_FULL_DUPLEX_STREAMED,
					ResponseTrailerMode: ext_procv3.ProcessingMode_SKIP,
				}
			}

			// log.Info().Msgf("Setting Response Body Mode to BUFFERED [%d]", rnd)
			// resp.ModeOverride = &ext_procv3.ProcessingMode{
			// 	ResponseBodyMode: ext_procv3.ProcessingMode_FULL_DUPLEX_STREAMED,
			// }

			if err := processServer.Send(resp); err != nil {
				log.Error().Err(err).Msg("Error sending response")
			}

		case *pb.ProcessingRequest_ResponseBody:
			body := value.ResponseBody.Body
			eos := value.ResponseBody.EndOfStream

			if isStreaming {
				// ── STREAMING PATH ────────────────────────────────────────────
				// Response has Transfer-Encoding: chunked or Content-Type: text/event-stream.
				// Envoy is in FULL_DUPLEX_STREAMED mode — body arrives as multiple chunks.
				// Each chunk must be echoed back via StreamedBodyResponse.
				log.Info().
					Int("chunk_bytes", len(body)).
					Bool("eos", eos).
					Msgf("[STREAMING-PATH] chunk arrived [%d]", rnd)

				var decodedBody []byte

				if contentEncoding == "gzip" {
					// Initialize pipe and gzip reader on first chunk
					if pipeReader == nil {
						pipeReader, pipeWriter = io.Pipe()
						decompressChan = make(chan []byte, 10)

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
							buf := make([]byte, 4096)
							for {
								n, err := gzipReader.Read(buf)
								if n > 0 {
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

					if _, err := pipeWriter.Write(body); err != nil {
						log.Error().Err(err).Msg("Failed to write to pipe")
					}
					if eos {
						pipeWriter.Close()
						log.Info().Msg("Closed pipe writer")
					}

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
							break readLoop
						}
					}
					decodedBody = allDecompressed.Bytes()
					if len(decodedBody) > 0 {
						log.Info().Msgf("Decompressed: %d bytes", len(decodedBody))
					}
				} else {
					decodedBody = body
				}

				// Parse SSE tokens for OpenAI streaming responses
				if len(decodedBody) > 0 {
					responseChunkIndex++
					tokens := parseSSETokens(string(decodedBody))
					if len(tokens) > 0 {
						totalTokensReceived += len(tokens)
						allTokensCollected = append(allTokensCollected, tokens...)
						log.Info().
							Int("chunk_index", responseChunkIndex).
							Int("tokens_in_chunk", len(tokens)).
							Int("running_total_tokens", totalTokensReceived).
							Strs("tokens", tokens).
							Msg("openai_tokens_chunk")
						fmt.Printf("[TOKEN_MONITOR] chunk=%d tokens_in_chunk=%d running_total=%d | %s\n",
							responseChunkIndex, len(tokens), totalTokensReceived, strings.Join(tokens, ""))
					} else {
						log.Info().
							Int("chunk_index", responseChunkIndex).
							Int("bytes", len(decodedBody)).
							Msg("openai_sse_chunk_no_tokens")
					}
				}

				if eos {
					log.Info().Msg("[STREAMING-PATH] EndOfStream reached")
					fullText := strings.Join(allTokensCollected, "")
					log.Info().
						Int("total_chunks", responseChunkIndex).
						Int("total_tokens", totalTokensReceived).
						Int("total_chars", len(fullText)).
						Str("full_text_preview", truncate(fullText, 200)).
						Msg("openai_tokens_summary")
					fmt.Printf("[TOKEN_MONITOR] SUMMARY total_chunks=%d total_tokens=%d total_chars=%d\n",
						responseChunkIndex, totalTokensReceived, len(fullText))
				}

				// Apply PII masking to the raw chunk before forwarding.
				maskedBody := maskPII(body, rnd)
				if !bytes.Equal(maskedBody, body) {
					log.Info().Msgf("[STREAMING-PATH] chunk mutated by PII masking [%d]", rnd)
				}

				// In FULL_DUPLEX_STREAMED mode: must echo each chunk back via StreamedBodyResponse.
				// Sending empty ack would drop the chunk — client would receive incomplete response.
				resp := &pb.ProcessingResponse{
					Response: &pb.ProcessingResponse_ResponseBody{
						ResponseBody: &pb.BodyResponse{
							Response: &pb.CommonResponse{
								BodyMutation: &pb.BodyMutation{
									Mutation: &pb.BodyMutation_StreamedResponse{
										StreamedResponse: &pb.StreamedBodyResponse{
											Body:        maskedBody,
											EndOfStream: eos,
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

			} else {
				// ── BUFFERED PATH ─────────────────────────────────────────────
				// Response has Content-Length — non-streaming, complete body.
				// ModeOverride=BUFFERED was sent at ResponseHeaders so Envoy assembled
				// the full body before calling us. EOS is always true here.
				// Use BodyMutation_Body (not StreamedBodyResponse) to return the complete body.
				// This preserves Content-Length on the downstream response and avoids
				// converting to Transfer-Encoding: chunked, which breaks some clients.
				log.Info().
					Int("body_bytes", len(body)).
					Bool("eos", eos).
					Msgf("[BUFFERED-PATH] complete body arrived [%d]", rnd)

				if !eos {
					// Should never happen when BUFFERED override was sent — log as warning
					log.Warn().Msgf("[BUFFERED-PATH] unexpected EOS=false in buffered mode [%d]", rnd)
				}

				decodedBody := body
				if contentEncoding == "gzip" {
					if decoded, err := decodeBody(body, contentEncoding); err == nil {
						decodedBody = decoded
					} else {
						log.Warn().Err(err).Msg("Failed to decode gzip body in buffered path")
					}
				}

				log.Info().
					Str("body_preview", truncate(string(decodedBody), 500)).
					Msgf("[BUFFERED-PATH] body content [%d]", rnd)

					// Apply PII masking on decoded (plaintext) body.
				maskedBody := maskPII(decodedBody, rnd)
				if !bytes.Equal(maskedBody, decodedBody) {
					log.Info().Msgf("[BUFFERED-PATH] body mutated by PII masking [%d]", rnd)
				}

				// In BUFFERED mode: use BodyMutation_Body with the complete body.
				resp := &pb.ProcessingResponse{
					Response: &pb.ProcessingResponse_ResponseBody{
						ResponseBody: &pb.BodyResponse{
							Response: &pb.CommonResponse{
								BodyMutation: &pb.BodyMutation{
									Mutation: &pb.BodyMutation_Body{
										Body: maskedBody,
									},
								},
							},
						},
					},
				}
				if err := processServer.Send(resp); err != nil {
					log.Error().Err(err).Msg("Error sending response")
				}
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
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
