package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"

	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

var writeDataToFile *bool

var _ ext_proc_v3.ExternalProcessorServer = &server{}

var newReqBodyChunks [][]byte
var newRespBodyChunks [][]byte

const chunkSize = 1 << 20 // 1 MiB

func splitIntoChunks(data []byte) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		size := chunkSize
		if len(data) < chunkSize {
			size = len(data)
		}
		chunks = append(chunks, data[:size])
		data = data[size:]
	}
	return chunks
}

type server struct{}

// streamState tracks per-request progress through the replacement body chunks.
// reqChunkIdx is the next replacement chunk to send for the request body.
// respChunkIdx is the next replacement chunk to send for the response body.
// The last chunk in each slice is always deferred to the original EOS event so
// that the replacement EndOfStream aligns with the original body's end.
type streamState struct {
	reqChunkIdx  int
	respChunkIdx int
}

func makeReqBodyResp(body []byte, eos bool) *pb.ProcessingResponse {
	return &pb.ProcessingResponse{
		Response: &pb.ProcessingResponse_RequestBody{
			RequestBody: &pb.BodyResponse{
				Response: &pb.CommonResponse{
					BodyMutation: &pb.BodyMutation{
						Mutation: &pb.BodyMutation_StreamedResponse{
							StreamedResponse: &pb.StreamedBodyResponse{
								Body:        body,
								EndOfStream: eos,
							},
						},
					},
				},
			},
		},
	}
}

func makeRespBodyResp(body []byte, eos bool) *pb.ProcessingResponse {
	return &pb.ProcessingResponse{
		Response: &pb.ProcessingResponse_ResponseBody{
			ResponseBody: &pb.BodyResponse{
				Response: &pb.CommonResponse{
					BodyMutation: &pb.BodyMutation{
						Mutation: &pb.BodyMutation_StreamedResponse{
							StreamedResponse: &pb.StreamedBodyResponse{
								Body:        body,
								EndOfStream: eos,
							},
						},
					},
				},
			},
		},
	}
}

func clearRespBodyChunk() *pb.ProcessingResponse {
	return &pb.ProcessingResponse{
		Response: &pb.ProcessingResponse_ResponseBody{
			ResponseBody: &pb.BodyResponse{
				Response: &pb.CommonResponse{
					BodyMutation: &pb.BodyMutation{
						Mutation: &pb.BodyMutation_ClearBody{
							ClearBody: true,
						},
					},
				},
			},
		},
	}
}

// Process implements ext_proc_v3.ExternalProcessorServer.
func (s *server) Process(stream ext_proc_v3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	rnd := rand.Int()
	state := &streamState{}

	var reqFile, respFile *os.File
	if *writeDataToFile {
		var err error
		reqFile, err = os.OpenFile(fmt.Sprintf("../temp/%d-request_payload.mp4", rnd), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Err(err).Msg("Error opening request dump file")
		} else {
			defer reqFile.Close()
		}
		respFile, err = os.OpenFile(fmt.Sprintf("../temp/%d-response_body.mp4", rnd), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Err(err).Msg("Error opening response dump file")
		} else {
			defer respFile.Close()
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Info().Err(err).Msg("Stream completed")
			return nil
		}

		switch value := req.Request.(type) {

		case *pb.ProcessingRequest_RequestHeaders:
			log.Info().Msgf("[%d] Request headers", rnd)
			if err := stream.Send(&pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_RequestHeaders{},
				ModeOverride: &ext_procv3.ProcessingMode{
					RequestBodyMode:     ext_procv3.ProcessingMode_FULL_DUPLEX_STREAMED,
					RequestTrailerMode:  ext_procv3.ProcessingMode_SEND,
					ResponseHeaderMode:  ext_procv3.ProcessingMode_SEND,
					ResponseBodyMode:    ext_procv3.ProcessingMode_BUFFERED,
					ResponseTrailerMode: ext_procv3.ProcessingMode_SEND,
				},
			}); err != nil {
				log.Error().Err(err).Msg("Error sending RequestHeaders response")
			}

		case *pb.ProcessingRequest_RequestBody:
			eos := value.RequestBody.EndOfStream
			log.Info().Msgf("[%d] Request body chunk (eos=%v reqIdx=%d)", rnd, eos, state.reqChunkIdx)

			if *writeDataToFile && reqFile != nil {
				if _, err := reqFile.Write(value.RequestBody.Body); err != nil {
					log.Error().Err(err).Msg("Error writing request body to file")
				}
			}

			if !eos {
				// Send the next replacement chunk to the upstream as a StreamedBodyResponse,
				// which replaces (suppresses) the original chunk.
				// The request→upstream direction uses HTTP/2, so empty DATA frames are safe.
				// We reserve the last replacement chunk for the EOS event.
				if state.reqChunkIdx < len(newReqBodyChunks)-1 {
					if err := stream.Send(makeReqBodyResp(newReqBodyChunks[state.reqChunkIdx], false)); err != nil {
						log.Error().Err(err).Msg("Error sending request replacement chunk")
					}
					state.reqChunkIdx++
				} else {
					// Replacement exhausted before original EOS — suppress original with empty body.
					// Safe over HTTP/2 (no HTTP/1.1 empty-chunk termination concern here).
					if err := stream.Send(makeReqBodyResp([]byte{}, false)); err != nil {
						log.Error().Err(err).Msg("Error suppressing request body chunk")
					}
				}
			} else {
				// Original body EOS: flush all remaining replacement chunks.
				// The last one carries EndOfStream=true to close the upstream request body.
				log.Info().Msgf("[%d] Request body EOS — flushing %d remaining replacement chunk(s)", rnd, len(newReqBodyChunks)-state.reqChunkIdx)
				for i := state.reqChunkIdx; i < len(newReqBodyChunks); i++ {
					isLast := i == len(newReqBodyChunks)-1
					if err := stream.Send(makeReqBodyResp(newReqBodyChunks[i], isLast)); err != nil {
						log.Error().Err(err).Msg("Error sending request replacement chunk on EOS")
					}
				}
			}

		case *pb.ProcessingRequest_ResponseHeaders:
			log.Info().Msgf("[%d] Response headers", rnd)
			// Remove content-length so the client is not constrained to the original
			// body size when we send a replacement of a different length.
			if err := stream.Send(&pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &pb.HeadersResponse{
						Response: &pb.CommonResponse{
							HeaderMutation: &pb.HeaderMutation{
								RemoveHeaders: []string{"content-length"},
							},
						},
					},
				},
				ModeOverride: &ext_procv3.ProcessingMode{
					RequestBodyMode:     ext_procv3.ProcessingMode_FULL_DUPLEX_STREAMED,
					RequestTrailerMode:  ext_procv3.ProcessingMode_SEND,
					ResponseHeaderMode:  ext_procv3.ProcessingMode_SEND,
					ResponseBodyMode:    ext_procv3.ProcessingMode_FULL_DUPLEX_STREAMED,
					ResponseTrailerMode: ext_procv3.ProcessingMode_SEND,
				},
			}); err != nil {
				log.Error().Err(err).Msg("Error sending ResponseHeaders response")
			}

		case *pb.ProcessingRequest_ResponseBody:
			eos := value.ResponseBody.EndOfStream
			log.Info().Msgf("[%d] Response body chunk (eos=%v respIdx=%d)", rnd, eos, state.respChunkIdx)

			if *writeDataToFile && respFile != nil {
				if _, err := respFile.Write(value.ResponseBody.Body); err != nil {
					log.Error().Err(err).Msg("Error writing response body to file")
				}
			}

			if !eos {
				// Send the next replacement chunk to the downstream client.
				// In FDS response direction, a StreamedBodyResponse replaces the original chunk.
				// We reserve the last replacement chunk for the EOS event.
				if state.respChunkIdx < len(newRespBodyChunks)-1 {
					if err := stream.Send(makeRespBodyResp(newRespBodyChunks[state.respChunkIdx], false)); err != nil {
						log.Error().Err(err).Msg("Error sending response replacement chunk")
					}
					state.respChunkIdx++
				} else {
					// Replacement exhausted — suppress this original chunk with clear_body.
					// Unlike StreamedBodyResponse{Body:[]byte{}}, clear_body does NOT emit
					// an HTTP/1.1 "0\r\n\r\n" empty chunk (which would terminate chunked
					// encoding). It simply discards the original chunk without forwarding
					// anything to the client.
					if err := stream.Send(clearRespBodyChunk()); err != nil {
						log.Error().Err(err).Msg("Error suppressing response body chunk")
					}
				}
			} else {
				// Original body EOS: flush all remaining replacement chunks.
				// The last one carries EndOfStream=true to close the downstream response body.
				log.Info().Msgf("[%d] Response body EOS — flushing %d remaining replacement chunk(s)", rnd, len(newRespBodyChunks)-state.respChunkIdx)
				for i := state.respChunkIdx; i < len(newRespBodyChunks); i++ {
					isLast := i == len(newRespBodyChunks)-1
					if err := stream.Send(makeRespBodyResp(newRespBodyChunks[i], isLast)); err != nil {
						log.Error().Err(err).Msg("Error sending response replacement chunk on EOS")
					}
				}
			}

		default:
			log.Warn().Msgf("[%d] Unknown request type: %T", rnd, value)
		}
	}
}

func main() {
	port := flag.Int("port", 9001, "gRPC port")
	writeDataToFile = flag.Bool("write_data_to_file", false, "write received body chunks to file for debugging")
	flag.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Request replacement is the smaller file so the backend echo (which equals
	// the request replacement size) stays smaller than the response replacement.
	reqBody, err := os.ReadFile("../resources/something_just_like_this.mp4")
	if err != nil {
		log.Fatal().Err(err).Msg("Error reading request replacement file")
	}
	newReqBodyChunks = splitIntoChunks(reqBody)
	log.Info().Msgf("Loaded request replacement: %d bytes, %d chunk(s)", len(reqBody), len(newReqBodyChunks))

	// Response replacement must be >= the request replacement in chunks so it
	// never exhausts (the backend echoes the request replacement as its response).
	respBody, err := os.ReadFile("../resources/roar.mp4")
	if err != nil {
		log.Fatal().Err(err).Msg("Error reading response replacement file")
	}
	newRespBodyChunks = splitIntoChunks(respBody)
	log.Info().Msgf("Loaded response replacement: %d bytes, %d chunk(s)", len(respBody), len(newRespBodyChunks))

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to listen on port %d", *port)
	}

	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(1024*1024*50), // 50 MB
		grpc.MaxSendMsgSize(1024*1024*50), // 50 MB
	)
	ext_proc_v3.RegisterExternalProcessorServer(gs, &server{})
	log.Info().Msgf("gRPC server listening on :%d", *port)
	if err := gs.Serve(lis); err != nil {
		log.Fatal().Err(err).Msg("Failed to serve")
	}
}
