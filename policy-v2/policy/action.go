package policy

// ─── Short-circuit ────────────────────────────────────────────────────────────

// ImmediateResponse terminates the policy chain and returns this response to
// the downstream client immediately. Used in header and buffered body hooks.
type ImmediateResponse struct {
	Status  int
	Headers map[string]string
	Body    []byte
	// Analytics fields still flow to the analytics backend even on short-circuit.
	AnalyticsMetadata        map[string]any
	DynamicMetadata          map[string]map[string]any
	DropHeadersFromAnalytics DropHeaderAction
}

// DropHeaderAction controls which headers appear in the analytics event.
type DropHeaderAction struct {
	Action  string   // "allow" (whitelist) or "deny" (blacklist)
	Headers []string // header names (case-insensitive)
}

// ─── Header phase actions ─────────────────────────────────────────────────────

// HeaderAction is returned by OnRequestHeaders and OnResponseHeaders.
// Only header mutations are allowed at this phase — body is not yet available.
// If ImmediateResponse is non-nil the chain short-circuits immediately.
type HeaderAction struct {
	Set               map[string]string   // overwrite header (last write wins)
	Remove            []string            // remove by name (case-insensitive)
	Append            map[string][]string // append values alongside existing
	ImmediateResponse *ImmediateResponse  // non-nil → stop chain, return to client
}

// ─── Buffered body actions ────────────────────────────────────────────────────
//
// Buffered hooks receive the complete body, so they have broader capability.
// The full request or response has not yet been forwarded — header and routing
// mutations can still be applied.

// RequestBodyAction is returned by RequestBodyPolicy.OnRequestBody.
//
// Because the request body is fully buffered before being forwarded upstream,
// header and routing mutations applied here are still effective.
type RequestBodyAction struct {
	BodyMutation      []byte             // nil = passthrough; []byte{} = clear body
	ImmediateResponse *ImmediateResponse // non-nil → reject, return to client now
	// Header mutations are valid here: the request has not left yet.
	HeaderMutation *HeaderAction
	// Routing mutations (also valid before the request is forwarded).
	PathMutation   *string
	MethodMutation *string
	QueryAdd       map[string][]string
	QueryRemove    []string
	// Analytics
	AnalyticsMetadata        map[string]any
	DynamicMetadata          map[string]map[string]any
	DropHeadersFromAnalytics DropHeaderAction
}

// ResponseBodyAction is returned by ResponseBodyPolicy.OnResponseBody.
//
// By this phase request headers are already committed to upstream, but the
// response has not yet been forwarded to the downstream client, so status
// and body can still be changed.
// Header mutations are intentionally omitted: response headers were processed
// in OnResponseHeaders and have been committed. Attempting to change them here
// would have no effect on most HTTP versions.
type ResponseBodyAction struct {
	BodyMutation      []byte             // nil = passthrough; []byte{} = clear body
	ImmediateResponse *ImmediateResponse // non-nil → replace entire response
	StatusCode        *int               // nil = no change
	// Analytics
	AnalyticsMetadata        map[string]any
	DynamicMetadata          map[string]map[string]any
	DropHeadersFromAnalytics DropHeaderAction
}

// ─── Streaming body actions ───────────────────────────────────────────────────
//
// Streaming hooks receive one chunk at a time. By the time chunks arrive,
// both request headers (sent upstream) and response headers (sent downstream)
// are already committed. Only the chunk content can be changed.
//
// ImmediateResponse is NOT available in streaming chunk actions:
//   - For request chunks: the upstream connection is already open; aborting
//     mid-stream requires closing the connection, which is Envoy's concern, not
//     the policy's. Use RequestHeaderPolicy to reject before the body starts.
//   - For response chunks: the client has already received the response headers
//     and status; injecting a new response mid-stream is impossible.
//
// If you need to conditionally reject based on body content, implement
// FullBodyRequired to degrade to buffered mode where ImmediateResponse works.

// RequestChunkAction is returned by StreamingRequestBodyPolicy.OnRequestBodyChunk.
//
// Only the chunk payload can be modified. Request headers, path, method, and
// query parameters are all committed — mutations to those fields are ignored.
//
// DropHeadersFromAnalytics is intentionally absent: it is a one-time filtering
// decision about which headers appear in the analytics event. Set it in
// HeaderAction (OnRequestHeaders) or RequestBodyAction — not per-chunk.
type RequestChunkAction struct {
	BodyMutation []byte // nil = passthrough; mutated chunk forwarded to upstream
	// Analytics — accumulates incremental data across chunks (e.g. token counts).
	AnalyticsMetadata map[string]any
	DynamicMetadata   map[string]map[string]any
}

// ResponseChunkAction is returned by StreamingResponseBodyPolicy.OnResponseBodyChunk.
//
// Only the chunk payload can be modified. Response status and headers are already
// committed to the downstream client — mutations to those fields are ignored.
// There is no ImmediateResponse: once streaming has started the client has
// received the response status line and headers and cannot receive a new response.
//
// DropHeadersFromAnalytics is intentionally absent for the same reason as
// RequestChunkAction — set it in HeaderAction (OnResponseHeaders) or ResponseBodyAction.
type ResponseChunkAction struct {
	BodyMutation []byte // nil = passthrough; mutated chunk forwarded to client
	// Analytics — accumulates incremental data across chunks (e.g. per-SSE-event token counts).
	AnalyticsMetadata map[string]any
	DynamicMetadata   map[string]map[string]any
}
