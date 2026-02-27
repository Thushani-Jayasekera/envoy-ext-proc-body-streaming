package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"

	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

var (
	writeDataToFile *bool
	tempDir         *string
)

type server struct{}

// isStreamingRequest inspects all request headers and returns true if any
// streaming indicator is detected:
//   - transfer-encoding: chunked
//   - content-type prefix: video/, audio/, multipart/
//   - x-streaming: true
func isStreamingRequest(headers *pb.HttpHeaders) bool {
	for _, header := range headers.GetHeaders().GetHeaders() {
		key := strings.ToLower(header.GetKey())
		value := strings.ToLower(header.GetValue())
		if rawVal := header.GetRawValue(); len(rawVal) > 0 {
			value = strings.ToLower(string(rawVal))
		}
		switch key {
		case "transfer-encoding":
			if strings.Contains(value, "chunked") {
				return true
			}
		case "content-type":
			if strings.HasPrefix(value, "video/") ||
				strings.HasPrefix(value, "audio/") ||
				strings.HasPrefix(value, "multipart/") {
				return true
			}
		case "x-streaming":
			if value == "true" {
				return true
			}
		}
	}
	return false
}

func (s *server) Process(processServer ext_proc_v3.ExternalProcessor_ProcessServer) error {
	rnd := rand.Int()
	var reqFile *os.File

	for {
		req, err := processServer.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Info().Err(err).Msgf("[%d] Stream connection lost", rnd)
			return nil
		}

		switch value := req.Request.(type) {

		case *pb.ProcessingRequest_RequestHeaders:
			streaming := isStreamingRequest(value.RequestHeaders)
			log.Info().Msgf("[%d] Phase: Request Headers | streaming=%v", rnd, streaming)

			if *writeDataToFile && streaming {
				fname := fmt.Sprintf("%s/%d-mode-override-upload.bin", *tempDir, rnd)
				if f, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY, 0644); err == nil {
					reqFile = f
					defer reqFile.Close()
				}
			}

			if streaming {
				// Override default BUFFERED mode to FULL_DUPLEX_STREAMED
				processServer.Send(&pb.ProcessingResponse{
					Response: &pb.ProcessingResponse_RequestHeaders{
						RequestHeaders: &pb.HeadersResponse{},
					},
					ModeOverride: &ext_procv3.ProcessingMode{
						RequestBodyMode:     ext_procv3.ProcessingMode_FULL_DUPLEX_STREAMED,
						ResponseHeaderMode:  ext_procv3.ProcessingMode_SEND,
						ResponseBodyMode:    ext_procv3.ProcessingMode_BUFFERED,
						RequestTrailerMode:  ext_procv3.ProcessingMode_SKIP,
						ResponseTrailerMode: ext_procv3.ProcessingMode_SKIP,
					},
				})
			} else {
				// Non-streaming request: stay in default BUFFERED mode
				processServer.Send(&pb.ProcessingResponse{
					Response: &pb.ProcessingResponse_RequestHeaders{
						RequestHeaders: &pb.HeadersResponse{},
					},
				})
			}

		case *pb.ProcessingRequest_RequestBody:
			log.Debug().Msgf("[%d] Request body chunk: %d bytes, eof=%v",
				rnd, len(value.RequestBody.Body), value.RequestBody.EndOfStream)

			if *writeDataToFile && reqFile != nil {
				reqFile.Write(value.RequestBody.Body)
			}

			// Immediate ACK for all chunks (FDS pass-through, no body mutation)
			processServer.Send(&pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_RequestBody{
					RequestBody: &pb.BodyResponse{},
				},
			})

		case *pb.ProcessingRequest_ResponseHeaders:
			log.Info().Msgf("[%d] Phase: Response Headers", rnd)
			// Empty ACK - no modifications needed
			processServer.Send(&pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &pb.HeadersResponse{},
				},
			})

		case *pb.ProcessingRequest_ResponseBody:
			log.Debug().Msgf("[%d] Response body: %d bytes, eof=%v",
				rnd, len(value.ResponseBody.Body), value.ResponseBody.EndOfStream)
			// Empty ACK - backend returns small JSON, no modification needed
			processServer.Send(&pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseBody{
					ResponseBody: &pb.BodyResponse{},
				},
			})
		}
	}
}

func main() {
	port := flag.Int("port", 9003, "gRPC port")
	writeDataToFile = flag.Bool("write_data_to_file", false, "write request body chunks to temp_dir")
	tempDir = flag.String("temp_dir", "/app/temp", "directory to write request body files")
	flag.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}

	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(1024*1024*100),
		grpc.MaxSendMsgSize(1024*1024*100),
	)
	ext_proc_v3.RegisterExternalProcessorServer(gs, &server{})
	log.Info().Msgf("gRPC server (mode-override) listening on port %d, temp_dir=%s", *port, *tempDir)
	gs.Serve(lis)
}
