package kernel

import (
	"context"
	"errors"
	"io"
	"log/slog"

	extproccfgv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"policy-v2/policy"
)

// Server implements the Envoy ExternalProcessor gRPC service.
// It routes each ext_proc phase to the appropriate ExecutionContext method.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	kernel *Kernel
}

// NewServer returns an ext_proc Server backed by the given Kernel.
func NewServer(k *Kernel) *Server {
	return &Server{kernel: k}
}

// Process is the bidirectional streaming RPC handler.
// One stream = one HTTP request-response lifecycle.
//
// Per-request state (ExecutionContext) is allocated lazily on the first
// RequestHeaders message and reused for all subsequent phases.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	var execCtx *ExecutionContext

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil || grpcstatus.Code(err) == grpccodes.Canceled {
				return nil // normal stream close
			}
			slog.Error("Stream receive error", "error", err)
			return grpcstatus.Errorf(grpccodes.Unknown, "recv: %v", err)
		}

		resp, err := s.dispatch(ctx, req, &execCtx)
		if err != nil {
			slog.Error("Dispatch error", "error", err)
			return grpcstatus.Errorf(grpccodes.Internal, "dispatch: %v", err)
		}

		if err := stream.Send(resp); err != nil {
			slog.Error("Stream send error", "error", err)
			return grpcstatus.Errorf(grpccodes.Unknown, "send: %v", err)
		}
	}
}

// dispatch routes each ext_proc phase to the correct handler.
func (s *Server) dispatch(
	ctx context.Context,
	req *extprocv3.ProcessingRequest,
	execCtx **ExecutionContext,
) (*extprocv3.ProcessingResponse, error) {
	switch req.Request.(type) {

	case *extprocv3.ProcessingRequest_RequestHeaders:
		headers := req.GetRequestHeaders()
		routeName := extractRouteName(req)

		chain := s.kernel.GetChain(routeName)
		if chain == nil {
			slog.Info("No policy chain for route — skipping all processing", "route", routeName)
			return skipAllProcessing(), nil
		}

		shared := &policy.SharedContext{
			RequestID: extractRequestID(headers),
			Metadata:  make(map[string]interface{}),
			AuthContext: make(map[string]string),
		}
		*execCtx = newExecutionContext(routeName, chain, shared)

		slog.Info("RequestHeaders", "route", routeName, "policies", len(chain.Policies))
		return (*execCtx).HandleRequestHeaders(ctx, headers), nil

	case *extprocv3.ProcessingRequest_RequestBody:
		if *execCtx == nil {
			slog.Warn("RequestBody received without execution context")
			return passthroughRequestBody(), nil
		}
		return (*execCtx).HandleRequestBody(ctx, req.GetRequestBody()), nil

	case *extprocv3.ProcessingRequest_ResponseHeaders:
		if *execCtx == nil {
			slog.Warn("ResponseHeaders received without execution context")
			return passthroughResponseHeaders(), nil
		}
		return (*execCtx).HandleResponseHeaders(ctx, req.GetResponseHeaders()), nil

	case *extprocv3.ProcessingRequest_ResponseBody:
		if *execCtx == nil {
			slog.Warn("ResponseBody received without execution context")
			return passthroughResponseBody(), nil
		}
		return (*execCtx).HandleResponseBody(ctx, req.GetResponseBody()), nil

	default:
		slog.Warn("Unknown request type", "type", req.Request)
		return passthroughResponseBody(), nil
	}
}

// ── Metadata extraction ───────────────────────────────────────────────────────

// extractRouteName reads the route name from Envoy request metadata.
//
// Priority order:
//  1. req.Attributes["envoy.filters.http.ext_proc"]["xds.route_name"]
//     (Envoy sends this automatically for named routes in newer versions)
//  2. req.MetadataContext.FilterMetadata["envoy.filters.http.ext_proc"]["route_name"]
//     (per-route filter_metadata configured in the Envoy YAML)
//
// Falls back to "default" if neither is present.
func extractRouteName(req *extprocv3.ProcessingRequest) string {
	// 1. Try xds.route_name from Attributes (newer Envoy versions).
	if req.Attributes != nil {
		if attrs, ok := req.Attributes["envoy.filters.http.ext_proc"]; ok && attrs != nil {
			if v, ok := attrs.Fields["xds.route_name"]; ok {
				if name := v.GetStringValue(); name != "" {
					return name
				}
			}
		}
	}

	// 2. Try route_name from per-route filter metadata (envoy YAML filter_metadata).
	if req.MetadataContext != nil {
		if fm, ok := req.MetadataContext.FilterMetadata["envoy.filters.http.ext_proc"]; ok && fm != nil {
			if v, ok := fm.Fields["route_name"]; ok {
				if name := v.GetStringValue(); name != "" {
					return name
				}
			}
		}
	}

	return "default"
}

// extractRequestID reads x-request-id from Envoy headers.
func extractRequestID(headers *extprocv3.HttpHeaders) string {
	if headers == nil || headers.Headers == nil {
		return ""
	}
	for _, h := range headers.Headers.GetHeaders() {
		if h.Key == "x-request-id" {
			return string(h.RawValue)
		}
	}
	return ""
}

// ── Passthrough responses ─────────────────────────────────────────────────────

// skipAllProcessing returns a response that disables all remaining ext_proc phases.
// Used when no policy chain is registered for the route.
func skipAllProcessing() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{},
		},
		ModeOverride: &extproccfgv3.ProcessingMode{
			RequestBodyMode:     extproccfgv3.ProcessingMode_NONE,
			ResponseBodyMode:    extproccfgv3.ProcessingMode_NONE,
			ResponseHeaderMode:  extproccfgv3.ProcessingMode_SKIP,
			RequestTrailerMode:  extproccfgv3.ProcessingMode_SKIP,
			ResponseTrailerMode: extproccfgv3.ProcessingMode_SKIP,
		},
	}
}

func passthroughRequestBody() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{},
		},
	}
}

func passthroughResponseHeaders() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{},
		},
	}
}

func passthroughResponseBody() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{},
		},
	}
}
