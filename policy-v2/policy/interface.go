// Package policy defines the v2 policy interface contract.
//
// # Capability declaration
//
// Policies declare capabilities by implementing phase-specific sub-interfaces.
// The kernel inspects these at chain-build time to determine the optimal Envoy
// body mode (BUFFERED vs FULL_DUPLEX_STREAMED) and to route each phase to the
// correct hook method.
//
// # Mode selection rules
//
//   - ANY body policy in the chain is NOT a streaming variant
//     → kernel forces BUFFERED for that body direction (request or response)
//   - ALL body policies implement the streaming variant
//     → kernel uses FULL_DUPLEX_STREAMED
//
// # Action types by phase
//
// The action types form a deliberate capability hierarchy that mirrors what
// is physically possible at each phase:
//
//	Header phase         → HeaderAction      (header mutations + optional ImmediateResponse)
//	Buffered request body → RequestBodyAction (headers + routing + body mutations)
//	Buffered response body → ResponseBodyAction (body + status; headers already committed)
//	Streaming request chunk → RequestChunkAction (body only; headers committed to upstream)
//	Streaming response chunk → ResponseChunkAction (body only; status+headers committed to client)
//
// This prevents policy authors from attempting mutations that are physically
// impossible at a given phase (e.g., changing a response status mid-stream).
//
// # Chunk accumulation
//
// Streaming policies may embed a ChunkBuffering strategy to hold raw Envoy
// chunks until a logical boundary is reached (e.g., SSE \n\n). Without
// ChunkBuffering every raw chunk is forwarded to the hook immediately.
//
// # Mixed-chain forced-buffering
//
// When the effective Envoy mode is BUFFERED (due to a co-located buffered-only
// policy), the kernel wraps the full body as a single synthetic chunk with
// EndOfStream=true and routes it through the streaming chunk handler. Policy
// behaviour is therefore consistent regardless of chain composition.
package policy

// Policy is a marker interface. Every policy must satisfy it.
// The policy name lives in the YAML definition — not here.
// Capabilities are declared by implementing the phase-specific sub-interfaces below.
type Policy interface{}

// PolicyFactory is the constructor signature every policy plugin must export
// as GetPolicy. All parameter parsing must happen here — hook methods must not
// accept params and must not allocate per-request.
type PolicyFactory func(metadata PolicyMetadata, params map[string]interface{}) (Policy, error)

// PolicyMetadata carries route-level context passed to GetPolicy.
type PolicyMetadata struct {
	RouteName  string
	APIId      string
	APIName    string
	APIVersion string
	AttachedTo Level
}

// Level indicates where in the API hierarchy the policy is attached.
type Level string

const (
	LevelAPI   Level = "api"
	LevelRoute Level = "route"
)

// ─── Header phase ─────────────────────────────────────────────────────────────
// Header hooks run before any body is read.

// RequestHeaderPolicy intercepts request headers before the body.
// Implement for early blocking, auth, or header rewriting that does not require
// the body. Returns HeaderAction which can mutate headers or short-circuit.
type RequestHeaderPolicy interface {
	OnRequestHeaders(ctx *RequestHeaderContext) HeaderAction
}

// ResponseHeaderPolicy intercepts response headers from upstream.
// Returns HeaderAction which can mutate response headers or short-circuit.
// Use ctx.Metadata to propagate decisions (e.g., "this is SSE") to body hooks.
type ResponseHeaderPolicy interface {
	OnResponseHeaders(ctx *ResponseHeaderContext) HeaderAction
}

// ─── Body phase: buffered ─────────────────────────────────────────────────────
// Buffered hooks receive the complete body in one call.
// If any policy implements only the buffered interface (not the streaming
// variant), the kernel forces BUFFERED for that direction.

// RequestBodyPolicy receives the fully buffered request body.
// Returns RequestBodyAction which supports header/routing/body mutations and
// ImmediateResponse, because the request has not yet been forwarded upstream.
type RequestBodyPolicy interface {
	OnRequestBody(ctx *RequestBodyContext) RequestBodyAction
}

// ResponseBodyPolicy receives the fully buffered response body.
// Returns ResponseBodyAction which supports body/status mutation and
// ImmediateResponse. Header mutations are not available because response headers
// were already processed in OnResponseHeaders.
type ResponseBodyPolicy interface {
	OnResponseBody(ctx *ResponseBodyContext) ResponseBodyAction
}

// ─── Body phase: streaming ────────────────────────────────────────────────────
// Streaming hooks are called per-chunk (or per-accumulated-event if ChunkBuffering
// is implemented). The embedded buffered interface is a required contract.
//
// When in forced-BUFFERED mode (due to a co-located non-streaming policy), the
// kernel delivers the full body as a single synthetic chunk with EndOfStream=true
// and routes it through the chunk handler. Policy behaviour is therefore
// consistent regardless of which other policies share the chain.

// StreamingRequestBodyPolicy extends RequestBodyPolicy with per-chunk processing.
//
// Returns RequestChunkAction (restricted vs RequestBodyAction) because by the
// time chunks arrive the request headers are already committed upstream.
// Use RequestHeaderPolicy for header mutations, or RequestBodyPolicy for full
// body access with ImmediateResponse capability.
type StreamingRequestBodyPolicy interface {
	RequestBodyPolicy // required: buffers the compile-time contract, used in forced-BUFFERED mode
	OnRequestBodyChunk(ctx *RequestStreamContext, chunk *StreamBody) RequestChunkAction
}

// StreamingResponseBodyPolicy extends ResponseBodyPolicy with per-chunk processing.
//
// Returns ResponseChunkAction (most restricted) because response status and
// headers are already committed to the downstream client. No ImmediateResponse
// is available — the client has already received the response status line.
// Embed SSEEventBuffer to flush per-SSE-event rather than per-raw-chunk.
type StreamingResponseBodyPolicy interface {
	ResponseBodyPolicy // required: buffered fallback contract
	OnResponseBodyChunk(ctx *ResponseStreamContext, chunk *StreamBody) ResponseChunkAction
}

// ─── Chunk buffering ──────────────────────────────────────────────────────────

// ChunkBuffering controls when the accumulated buffer is flushed to the chunk
// handler. Implement this on your streaming policy to opt into accumulation.
//
// Framework logic:
//   - ANY policy NeedsMoreData → hold (suppress chunk downstream)
//   - ALL policies ready       → flush (run chain on accumulated buffer)
//   - eos = true               → kernel flushes unconditionally; NeedsMoreData
//     is NOT called on the final chunk — the policy never needs to inspect eos.
//
// Warning: chunks are suppressed during the hold phase, so the client receives
// no data until the flush boundary. Only hold on chunk-aligned delimiters
// (e.g. SSE \n\n) to avoid unbounded latency.
//
// Use the utility functions in buffering.go to implement NeedsMoreData:
//
//	func (p *MyPolicy) NeedsMoreData(accumulated []byte) bool {
//	    return policy.NeedsMoreDataSSE(accumulated)
//	}
type ChunkBuffering interface {
	NeedsMoreData(accumulated []byte) bool
}

