package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

var write_data_to_file *bool

var _ ext_proc_v3.ExternalProcessorServer = &server{}

type server struct {
}

// Process implements ext_procv3.ExternalProcessorServer.
func (s *server) Process(processServer ext_proc_v3.ExternalProcessor_ProcessServer) error {
	ctx := processServer.Context()
	rnd := rand.Int()

	req_payload_file := &os.File{}
	var err error
	if *write_data_to_file {
		req_payload_filename := fmt.Sprintf("../temp/%d-request_payload.mp4", rnd)
		req_payload_file, err = os.OpenFile(req_payload_filename, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening or creating file:", err)
		}
		defer req_payload_file.Close()
	}

	resp_payload_file := &os.File{}
	if *write_data_to_file {
		resp_payload_filename := fmt.Sprintf("../temp/%d-response_body.mp4", rnd)
		resp_payload_file, err = os.OpenFile(resp_payload_filename, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening or creating file:", err)
		}
		defer resp_payload_file.Close()
	}

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
					RequestBodyMode:     ext_procv3.ProcessingMode_BUFFERED,
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

			if *write_data_to_file {
				_, err = req_payload_file.Write(body)
				if err != nil {
					log.Error().Err(err).Msg("Error writing to file")
				}
			}

			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_RequestBody{
					RequestBody: &pb.BodyResponse{
						Response: &pb.CommonResponse{
							BodyMutation: &pb.BodyMutation{
								Mutation: &pb.BodyMutation_Body{
									Body: []byte("<http><body><h1>Request Body Replaced by External Processor</h1></body></html>"),
								},
							},
							HeaderMutation: &pb.HeaderMutation{
								SetHeaders: []*corev3.HeaderValueOption{
									{
										Header: &corev3.HeaderValue{
											Key:      "Content-Length",
											RawValue: []byte("78"),
										},
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

			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseHeaders{},
			}

			if err := processServer.Send(resp); err != nil {
				log.Error().Err(err).Msg("Error sending response")
			}

		case *pb.ProcessingRequest_ResponseBody:
			log.Info().Msgf("******** Processing Response Body ********* %v", rnd)

			body := value.ResponseBody.Body
			if *write_data_to_file {
				_, err = resp_payload_file.Write(body)
				if err != nil {
					log.Error().Err(err).Msg("Error writing to file")
				}
			}

			resp := &pb.ProcessingResponse{
				Response: &pb.ProcessingResponse_ResponseBody{
					ResponseBody: &pb.BodyResponse{
						Response: &pb.CommonResponse{
							BodyMutation: &pb.BodyMutation{
								Mutation: &pb.BodyMutation_Body{
									Body: []byte("<http><body><h1>Response Body Replaced by External Processor</h1></body></html>"),
								},
							},
							HeaderMutation: &pb.HeaderMutation{
								SetHeaders: []*corev3.HeaderValueOption{
									{
										Header: &corev3.HeaderValue{
											Key:      "Content-Length",
											RawValue: []byte("79"),
										},
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
	write_data_to_file = flag.Bool("write_data_to_file", false, "write data to file")
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
