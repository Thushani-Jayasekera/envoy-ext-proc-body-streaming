package kernel

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	extproccfgv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"policy-v2/policy"
)

// ExecutionContext manages the full request-response lifecycle for a single
// Envoy ext_proc stream (one HTTP request).
type ExecutionContext struct {
	chain    *PolicyChain
	routeKey string

	// Shared across all phases — the same pointer is embedded in every context struct
	// so that inter-policy metadata (e.g. PII masking placeholders) propagates
	// from request body → response body automatically.
	shared *policy.SharedContext

	// Request phase state.
	reqHeaders   *policy.Headers
	reqPath      string
	reqMethod    string
	reqAuthority string
	reqScheme    string

	// Response phase state — populated at ResponseHeaders.
	respHeaders *policy.Headers
	respStatus  int

	// isStreaming is set at ResponseHeaders by inspecting upstream response headers.
	// It determines whether the response body is delivered in FDS (chunked/SSE) or
	// BUFFERED (Content-Length) mode.
	isStreaming bool

	// accumBuf holds raw response chunks while ChunkBuffering policies are still
	// requesting more data.  Flushed when all policies are ready or EOS arrives.
	accumBuf []byte
}

// newExecutionContext creates an ExecutionContext for a new request.
func newExecutionContext(routeKey string, chain *PolicyChain, shared *policy.SharedContext) *ExecutionContext {
	return &ExecutionContext{
		routeKey: routeKey,
		chain:    chain,
		shared:   shared,
	}
}

// ── Request Headers ───────────────────────────────────────────────────────────

// HandleRequestHeaders processes the RequestHeaders phase.
// It runs all RequestHeaderPolicy hooks, builds the initial ModeOverride, and
// returns a ProcessingResponse.
//
// ModeOverride strategy (from MEMORY.md):
//   - Default BUFFERED for response body; upgraded to FDS at ResponseHeaders if streaming detected.
//   - This preserves Content-Length for non-streaming responses.
func (ec *ExecutionContext) HandleRequestHeaders(
	_ context.Context,
	headers *extprocv3.HttpHeaders,
) *extprocv3.ProcessingResponse {
	// Build request header state.
	hmap := make(map[string][]string)
	for _, h := range headers.GetHeaders().GetHeaders() {
		key := strings.ToLower(h.Key)
		val := string(h.RawValue)
		hmap[key] = append(hmap[key], val)
		switch key {
		case ":path":
			ec.reqPath = val
		case ":method":
			ec.reqMethod = val
		case ":authority":
			ec.reqAuthority = val
		case ":scheme":
			ec.reqScheme = val
		}
	}
	ec.reqHeaders = policy.NewHeaders(hmap)

	// Run header-phase policies.
	reqHdrCtx := &policy.RequestHeaderContext{
		SharedContext: ec.shared,
		Headers:       ec.reqHeaders,
		Path:          ec.reqPath,
		Method:        ec.reqMethod,
		Authority:     ec.reqAuthority,
		Scheme:        ec.reqScheme,
	}
	action, shortCircuit := ec.runRequestHeaders(reqHdrCtx)
	if shortCircuit != nil {
		return shortCircuit
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{
				Response: headerActionToCommonResponse(action),
			},
		},
		ModeOverride: ec.requestModeOverride(),
	}
}

// requestModeOverride returns the ProcessingMode set at RequestHeaders time.
//
// Key invariant (from MEMORY.md):
//   - ResponseBodyMode defaults to BUFFERED here — prevents Envoy from stripping
//     Content-Length before we know whether the upstream is streaming.
//   - At ResponseHeaders we may upgrade to FULL_DUPLEX_STREAMED if isStreaming is true.
func (ec *ExecutionContext) requestModeOverride() *extproccfgv3.ProcessingMode {
	mode := &extproccfgv3.ProcessingMode{
		RequestTrailerMode:  extproccfgv3.ProcessingMode_SKIP,
		ResponseTrailerMode: extproccfgv3.ProcessingMode_SKIP,
	}

	// Request body mode.
	if ec.chain.HasRequestBody {
		if ec.chain.StreamRequestBody {
			mode.RequestBodyMode = extproccfgv3.ProcessingMode_FULL_DUPLEX_STREAMED
		} else {
			mode.RequestBodyMode = extproccfgv3.ProcessingMode_BUFFERED
		}
	} else {
		mode.RequestBodyMode = extproccfgv3.ProcessingMode_NONE
	}

	// Response header mode — needed to detect streaming at ResponseHeaders.
	if ec.chain.HasResponseHeader || ec.chain.HasResponseBody {
		mode.ResponseHeaderMode = extproccfgv3.ProcessingMode_SEND
	} else {
		mode.ResponseHeaderMode = extproccfgv3.ProcessingMode_SKIP
	}

	// Response body — default BUFFERED; will be overridden at ResponseHeaders
	// if the upstream turns out to be streaming.
	if ec.chain.HasResponseBody {
		mode.ResponseBodyMode = extproccfgv3.ProcessingMode_BUFFERED
	} else {
		mode.ResponseBodyMode = extproccfgv3.ProcessingMode_NONE
	}

	return mode
}

// ── Request Body ─────────────────────────────────────────────────────────────

// HandleRequestBody processes the RequestBody phase.
// The body is always delivered in BUFFERED mode (see requestModeOverride),
// so OnRequestBody is called with the complete body.
// StreamingRequestBodyPolicy policies use their buffered fallback OnRequestBody.
func (ec *ExecutionContext) HandleRequestBody(
	_ context.Context,
	body *extprocv3.HttpBody,
) *extprocv3.ProcessingResponse {
	bodyCtx := &policy.RequestBodyContext{
		SharedContext: ec.shared,
		Headers:       ec.reqHeaders,
		Body: &policy.Body{
			Content:     body.Body,
			EndOfStream: body.EndOfStream,
			Present:     true,
		},
		Path:      ec.reqPath,
		Method:    ec.reqMethod,
		Authority: ec.reqAuthority,
	}

	action, shortCircuit := ec.runRequestBody(bodyCtx)
	if shortCircuit != nil {
		return shortCircuit
	}

	cr := &extprocv3.CommonResponse{}
	if action.BodyMutation != nil {
		cr.BodyMutation = &extprocv3.BodyMutation{
			Mutation: &extprocv3.BodyMutation_Body{Body: action.BodyMutation},
		}
		// Update content-length to match mutated body.
		cr.HeaderMutation = buildContentLengthMutation(len(action.BodyMutation))
	}
	if action.HeaderMutation != nil {
		if cr.HeaderMutation == nil {
			cr.HeaderMutation = headerActionToHeaderMutation(action.HeaderMutation)
		} else {
			mergeIntoHeaderMutation(cr.HeaderMutation, action.HeaderMutation)
		}
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: cr},
		},
	}
}

// ── Response Headers ──────────────────────────────────────────────────────────

// HandleResponseHeaders processes the ResponseHeaders phase.
//
// This is the "point of no return" for streaming detection (MEMORY.md):
//   - Inspect transfer-encoding / content-type to set ec.isStreaming.
//   - If streaming AND chain supports streaming → override ResponseBodyMode to FDS.
//   - Otherwise → keep BUFFERED (either non-streaming response or buffered-only chain).
func (ec *ExecutionContext) HandleResponseHeaders(
	_ context.Context,
	headers *extprocv3.HttpHeaders,
) *extprocv3.ProcessingResponse {
	hmap := make(map[string][]string)
	var transferEncoding, contentType string

	for _, h := range headers.GetHeaders().GetHeaders() {
		key := strings.ToLower(h.Key)
		val := string(h.RawValue)
		hmap[key] = append(hmap[key], val)

		if key == ":status" {
			fmt.Sscanf(val, "%d", &ec.respStatus)
		}
		if key == "transfer-encoding" {
			transferEncoding = val
		}
		if key == "content-type" {
			contentType = val
		}
	}
	ec.respHeaders = policy.NewHeaders(hmap)

	// Streaming detection (mirrors external-processor-full-duplex-stream-ai/main.go).
	isChunked := strings.Contains(strings.ToLower(transferEncoding), "chunked")
	isSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream")
	ec.isStreaming = isChunked || isSSE

	slog.Info("ResponseHeaders streaming detection",
		"route", ec.routeKey,
		"transfer-encoding", transferEncoding,
		"content-type", contentType,
		"is_chunked", isChunked,
		"is_sse", isSSE,
		"is_streaming", ec.isStreaming,
		"chain_stream_response", ec.chain.StreamResponseBody,
	)

	// Run response header policies.
	respHdrCtx := &policy.ResponseHeaderContext{
		SharedContext:   ec.shared,
		RequestHeaders:  ec.reqHeaders,
		ResponseHeaders: ec.respHeaders,
		ResponseStatus:  ec.respStatus,
	}
	action, _ := ec.runResponseHeaders(respHdrCtx)

	resp := &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{
				Response: headerActionToCommonResponse(action),
			},
		},
		ModeOverride: ec.responseModeOverride(),
	}
	return resp
}

// responseModeOverride returns the ProcessingMode override sent at ResponseHeaders.
//
// Decision matrix:
//   - isStreaming=true  && StreamResponseBody=true  → FDS  (streaming UX preserved)
//   - isStreaming=true  && StreamResponseBody=false → BUFFERED (chain needs full body)
//   - isStreaming=false && any                      → BUFFERED (Content-Length response)
//   - HasResponseBody=false                         → NONE    (chain doesn't need body)
func (ec *ExecutionContext) responseModeOverride() *extproccfgv3.ProcessingMode {
	if !ec.chain.HasResponseBody {
		return nil
	}

	mode := &extproccfgv3.ProcessingMode{
		RequestTrailerMode:  extproccfgv3.ProcessingMode_SKIP,
		ResponseTrailerMode: extproccfgv3.ProcessingMode_SKIP,
		ResponseHeaderMode:  extproccfgv3.ProcessingMode_SEND,
	}

	if ec.isStreaming && ec.chain.StreamResponseBody {
		slog.Info("Mode override: FULL_DUPLEX_STREAMED (streaming response + streaming chain)", "route", ec.routeKey)
		mode.ResponseBodyMode = extproccfgv3.ProcessingMode_FULL_DUPLEX_STREAMED
	} else {
		if ec.isStreaming {
			slog.Info("Mode override: BUFFERED (streaming response but chain needs full body)", "route", ec.routeKey)
		} else {
			slog.Info("Mode override: BUFFERED (non-streaming response)", "route", ec.routeKey)
		}
		mode.ResponseBodyMode = extproccfgv3.ProcessingMode_BUFFERED
	}

	return mode
}

// ── Response Body ─────────────────────────────────────────────────────────────

// HandleResponseBody is called by Envoy for every response body message.
// In BUFFERED mode this is called once with the complete body (eos=true).
// In FULL_DUPLEX_STREAMED mode this is called once per raw Envoy chunk.
//
// Routing matrix — decided at ResponseHeaders time using isStreaming and chain flags:
//
//	┌──────────────────────────────────────────────────┬──────────────────────────────────────────────┐
//	│ Condition                                         │ Path taken                                   │
//	├──────────────────────────────────────────────────┼──────────────────────────────────────────────┤
//	│ isStreaming=true  && chain.StreamResponseBody=true│ handleStreamingResponseBody                  │
//	│  - Upstream sends SSE or chunked transfer         │   → OnResponseBodyChunk (per flush)          │
//	│  - All policies implement streaming variant       │   Content: SSE event chunk or plain JSON     │
//	│  - Envoy mode: FULL_DUPLEX_STREAMED               │   assembled by NeedsMoreData accumulation    │
//	├──────────────────────────────────────────────────┼──────────────────────────────────────────────┤
//	│ isStreaming=true  && chain.StreamResponseBody=false│ handleBufferedResponseBody                  │
//	│  - Upstream sends SSE or chunked transfer         │   → OnResponseBody (buffered fallback)       │
//	│  - At least one policy is buffered-only           │   Content: ALL SSE chunks concatenated by    │
//	│  - Envoy mode: BUFFERED (kernel override)         │   Envoy into a single body string            │
//	├──────────────────────────────────────────────────┼──────────────────────────────────────────────┤
//	│ isStreaming=false && any chain                    │ handleBufferedResponseBody                   │
//	│  - Upstream sends Content-Length (plain JSON)     │   → OnResponseBody (buffered fallback)       │
//	│  - Envoy mode: BUFFERED (kernel default)          │   Content: complete plain JSON object        │
//	└──────────────────────────────────────────────────┴──────────────────────────────────────────────┘
func (ec *ExecutionContext) HandleResponseBody(
	_ context.Context,
	body *extprocv3.HttpBody,
) *extprocv3.ProcessingResponse {
	chunk := body.Body
	eos := body.EndOfStream

	if ec.isStreaming && ec.chain.StreamResponseBody {
		return ec.handleStreamingResponseBody(chunk, eos)
	}
	return ec.handleBufferedResponseBody(chunk, eos)
}

// handleStreamingResponseBody processes one raw Envoy chunk in FULL_DUPLEX_STREAMED mode.
// Called when: isStreaming=true AND chain.StreamResponseBody=true.
//
// The content arriving here can be EITHER:
//   - SSE events (streaming:true) — each raw Envoy chunk is part of a "data: {...}\n\n" stream
//   - Plain JSON in chunks (streaming:false but chunked HTTP transfer) — raw pieces of one JSON object
//
// ChunkBuffering strategy (controlled by policy.NeedsMoreData):
//
//  1. Append incoming raw chunk to accumBuf.
//  2. If eos=true → flush unconditionally (kernel never calls NeedsMoreData on final chunk).
//     If eos=false → ask each ChunkBuffering policy: NeedsMoreData(accumBuf)?
//     - ANY policy returns true → hold: suppress this chunk (send empty ack to Envoy).
//       The client receives nothing yet.  No unmasked data leaks downstream.
//     - ALL policies return false → flush: run the chain on accumBuf.
//  3. On flush: run OnResponseBodyChunk on each policy with the accumulated buffer.
//     Send the (possibly mutated) result downstream as StreamedBodyResponse.
//  4. Reset accumBuf for the next accumulation window.
//
// With NeedsMoreDataSSE as the strategy:
//   - SSE streams: flushes one complete event per "\n\n" boundary.
//   - Chunked JSON: holds all chunks until eos=true → delivers complete JSON in one call.
//
// ⚠ Hold = suppress (not echo).  Raw chunks are NOT forwarded during the hold phase.
// This prevents partially-processed content (e.g. unmasked PII) from reaching the client.
func (ec *ExecutionContext) handleStreamingResponseBody(chunk []byte, eos bool) *extprocv3.ProcessingResponse {
	ec.accumBuf = append(ec.accumBuf, chunk...)

	// Check whether any ChunkBuffering policy needs more data.
	// NeedsMoreData is only consulted on non-final chunks — when eos=true the
	// kernel flushes unconditionally and never calls NeedsMoreData.
	needsMore := false
	if !eos {
		for _, p := range ec.chain.Policies {
			if cb, ok := p.(policy.ChunkBuffering); ok {
				if cb.NeedsMoreData(ec.accumBuf) {
					needsMore = true
					break
				}
			}
		}
	}

	if needsMore {
		// Hold: suppress this chunk downstream.
		// Send an empty StreamedBodyResponse to ack the chunk without forwarding content.
		slog.Debug("ChunkBuffering: holding chunk", "route", ec.routeKey, "accum_bytes", len(ec.accumBuf))
		return emptyStreamedAck()
	}

	// Flush: run policies on the accumulated buffer.
	toProcess := ec.accumBuf
	ec.accumBuf = nil

	streamCtx := &policy.ResponseStreamContext{
		SharedContext:   ec.shared,
		RequestHeaders:  ec.reqHeaders,
		ResponseHeaders: ec.respHeaders,
		ResponseStatus:  ec.respStatus,
	}
	streamBody := &policy.StreamBody{Content: toProcess, EndOfStream: eos}

	resultBody := toProcess // default: passthrough
	for _, p := range ec.chain.Policies {
		if sp, ok := p.(policy.StreamingResponseBodyPolicy); ok {
			action := sp.OnResponseBodyChunk(streamCtx, streamBody)
			if action.BodyMutation != nil {
				resultBody = action.BodyMutation
				streamBody = &policy.StreamBody{Content: resultBody, EndOfStream: eos}
			}
		}
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{
					BodyMutation: &extprocv3.BodyMutation{
						Mutation: &extprocv3.BodyMutation_StreamedResponse{
							StreamedResponse: &extprocv3.StreamedBodyResponse{
								Body:        resultBody,
								EndOfStream: eos,
							},
						},
					},
				},
			},
		},
	}
}

// handleBufferedResponseBody processes the response body in BUFFERED mode.
// Called when: isStreaming=false OR chain.StreamResponseBody=false.
// Envoy always delivers the complete body as a single call with eos=true in BUFFERED mode.
// Uses BodyMutation_Body (not StreamedBodyResponse) which preserves Content-Length on
// the downstream response — correct for non-streaming clients.
//
// The content arriving here can be EITHER:
//
//   Plain JSON (isStreaming=false):
//     Upstream sent Content-Length response. One complete JSON object.
//     {"id":"chatcmpl-xxx","object":"chat.completion","choices":[...],...}
//
//   Aggregated SSE (isStreaming=true, chain.StreamResponseBody=false):
//     Upstream sent SSE but the chain has a buffered-only policy.  Envoy assembled
//     all SSE chunks into one body string before calling ext_proc.
//     data: {"choices":[{"delta":{"content":"Hello "}}]}\n\n
//     data: {"choices":[{"delta":{"content":"[EMAIL_0001]"}}]}\n\n
//     ...
//     data: [DONE]\n\n
//
// StreamingResponseBodyPolicy policies use their buffered fallback (OnResponseBody),
// which must handle both content formats above via format-agnostic string operations.
func (ec *ExecutionContext) handleBufferedResponseBody(body []byte, eos bool) *extprocv3.ProcessingResponse {
	if !eos {
		// Should never happen in BUFFERED mode — log and pass through.
		slog.Warn("Buffered response body: unexpected eos=false", "route", ec.routeKey)
	}

	bodyCtx := &policy.ResponseBodyContext{
		SharedContext:   ec.shared,
		RequestHeaders:  ec.reqHeaders,
		ResponseHeaders: ec.respHeaders,
		ResponseBody: &policy.Body{
			Content:     body,
			EndOfStream: eos,
			Present:     true,
		},
		ResponseStatus: ec.respStatus,
	}

	resultBody := body
	for _, p := range ec.chain.Policies {
		if sp, ok := p.(policy.StreamingResponseBodyPolicy); ok {
			// Use buffered fallback.
			action := sp.OnResponseBody(bodyCtx)
			if action.BodyMutation != nil {
				resultBody = action.BodyMutation
				bodyCtx.ResponseBody = &policy.Body{Content: resultBody, EndOfStream: eos, Present: true}
			}
		} else if bp, ok := p.(policy.ResponseBodyPolicy); ok {
			action := bp.OnResponseBody(bodyCtx)
			if action.BodyMutation != nil {
				resultBody = action.BodyMutation
				bodyCtx.ResponseBody = &policy.Body{Content: resultBody, EndOfStream: eos, Present: true}
			}
		}
	}

	cr := &extprocv3.CommonResponse{}
	if resultBody != nil && string(resultBody) != string(body) {
		cr.BodyMutation = &extprocv3.BodyMutation{
			Mutation: &extprocv3.BodyMutation_Body{Body: resultBody},
		}
		cr.HeaderMutation = buildContentLengthMutation(len(resultBody))
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{Response: cr},
		},
	}
}

// ── Chain runners ─────────────────────────────────────────────────────────────

func (ec *ExecutionContext) runRequestHeaders(ctx *policy.RequestHeaderContext) (policy.HeaderAction, *extprocv3.ProcessingResponse) {
	var combined policy.HeaderAction
	for _, p := range ec.chain.Policies {
		hp, ok := p.(policy.RequestHeaderPolicy)
		if !ok {
			continue
		}
		action := hp.OnRequestHeaders(ctx)
		if action.ImmediateResponse != nil {
			return policy.HeaderAction{}, immediateResponse(action.ImmediateResponse)
		}
		mergeHeaderAction(&combined, action)
	}
	return combined, nil
}

func (ec *ExecutionContext) runRequestBody(ctx *policy.RequestBodyContext) (policy.RequestBodyAction, *extprocv3.ProcessingResponse) {
	var combined policy.RequestBodyAction
	for _, p := range ec.chain.Policies {
		var action policy.RequestBodyAction
		if sp, ok := p.(policy.StreamingRequestBodyPolicy); ok {
			action = sp.OnRequestBody(ctx) // buffered fallback
		} else if bp, ok := p.(policy.RequestBodyPolicy); ok {
			action = bp.OnRequestBody(ctx)
		} else {
			continue
		}
		if action.ImmediateResponse != nil {
			return policy.RequestBodyAction{}, immediateResponse(action.ImmediateResponse)
		}
		mergeRequestBodyAction(&combined, action)
	}
	return combined, nil
}

func (ec *ExecutionContext) runResponseHeaders(ctx *policy.ResponseHeaderContext) (policy.HeaderAction, *extprocv3.ProcessingResponse) {
	var combined policy.HeaderAction
	for _, p := range ec.chain.Policies {
		hp, ok := p.(policy.ResponseHeaderPolicy)
		if !ok {
			continue
		}
		action := hp.OnResponseHeaders(ctx)
		if action.ImmediateResponse != nil {
			return policy.HeaderAction{}, immediateResponse(action.ImmediateResponse)
		}
		mergeHeaderAction(&combined, action)
	}
	return combined, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// immediateResponse converts a v2 ImmediateResponse into an ext_proc short-circuit response.
func immediateResponse(ir *policy.ImmediateResponse) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode(ir.Status)},
				Headers: buildHeaderMutation(ir.Headers),
				Body:    ir.Body,
			},
		},
	}
}

// emptyStreamedAck sends an empty StreamedBodyResponse to ack a held chunk without
// forwarding content downstream.
func emptyStreamedAck() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{
					BodyMutation: &extprocv3.BodyMutation{
						Mutation: &extprocv3.BodyMutation_StreamedResponse{
							StreamedResponse: &extprocv3.StreamedBodyResponse{
								Body:        []byte{},
								EndOfStream: false,
							},
						},
					},
				},
			},
		},
	}
}

// mergeHeaderAction merges src into dst (last Set wins, appends accumulate, removes accumulate).
func mergeHeaderAction(dst *policy.HeaderAction, src policy.HeaderAction) {
	if dst.Set == nil {
		dst.Set = make(map[string]string)
	}
	for k, v := range src.Set {
		dst.Set[k] = v
	}
	dst.Remove = append(dst.Remove, src.Remove...)
	if dst.Append == nil {
		dst.Append = make(map[string][]string)
	}
	for k, vs := range src.Append {
		dst.Append[k] = append(dst.Append[k], vs...)
	}
}

// mergeRequestBodyAction merges src into dst (last BodyMutation wins).
func mergeRequestBodyAction(dst *policy.RequestBodyAction, src policy.RequestBodyAction) {
	if src.BodyMutation != nil {
		dst.BodyMutation = src.BodyMutation
	}
	if src.HeaderMutation != nil {
		dst.HeaderMutation = src.HeaderMutation
	}
}
