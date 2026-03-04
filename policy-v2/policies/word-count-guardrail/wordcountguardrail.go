// Package wordcountguardrail implements word count validation for request and
// response bodies as a blocking guardrail policy.
//
// # Request side (buffered — RequestBodyPolicy)
//
// The request body is always fully buffered so JSONPath extraction and word
// counting can operate on the complete payload. Returns RequestBodyAction which
// can carry an ImmediateResponse (HTTP 422) if the word count violates the
// configured range.
//
// JSONPath (e.g. "$.messages[0].content") narrows validation to a specific field
// rather than counting words in the entire raw JSON body (which would include
// key names, punctuation, etc.).
//
// # Response side (buffered — ResponseBodyPolicy only, NOT streaming)
//
// Word count validation is a full-body operation — you cannot determine whether
// a response contains enough (or too many) words until all of the text is
// available. For this reason the response side implements ONLY ResponseBodyPolicy
// and not StreamingResponseBodyPolicy.
//
// Consequence for the chain: any chain containing this policy will have
// StreamResponseBody=false, which forces the kernel to use BUFFERED mode for the
// response body direction. When the upstream LLM is streaming (SSE / chunked),
// Envoy assembles all chunks before ext_proc receives the body. This adds end-to-
// end latency equal to the full LLM generation time, but is the only correct way
// to count words across the complete response.
//
// # Response content extraction — format-aware, user-configurable paths
//
// The assembled response body may arrive in one of two formats depending on
// whether the client requested streaming:
//
//	Plain JSON (stream:false):
//	  {"id":"chatcmpl-xxx","choices":[{"message":{"content":"Hello world"}}],...}
//	  → response.jsonPath is used (e.g. "$.choices[0].message.content").
//	    If empty the full body string is validated.
//
//	Aggregated SSE (stream:true, forced-BUFFERED by this policy):
//	  data: {"choices":[{"delta":{"content":"Hello "}}]}\n\n
//	  data: {"choices":[{"delta":{"content":"world"}}]}\n\n
//	  data: [DONE]\n\n
//	  → response.streamingJsonPath is applied per SSE event and all extracted
//	    values are concatenated (e.g. "$.choices[0].delta.content").
//	    If streamingJsonPath is empty the policy falls back to auto-extraction:
//	    it tries delta.content then message.content for each event.
//
// Why two separate paths are necessary:
//
//	Non-streaming:  choices[0].message.content  (full chat.completion object)
//	Streaming SSE:  choices[0].delta.content    (chat.completion.chunk per event)
//
// A single jsonPath cannot address both shapes. Operators configure whichever
// paths their LLM provider uses. Both fields default to empty (auto-extract).
//
// Example config:
//
//	response:
//	  min: 10
//	  max: 1000
//	  jsonPath:          "$.choices[0].message.content"   # plain JSON
//	  streamingJsonPath: "$.choices[0].delta.content"     # per SSE event
//
// # Violation behaviour
//
//   - Request violation → ImmediateResponse (HTTP 422) before the request
//     reaches the upstream. The LLM is never called.
//   - Response violation → ResponseBodyAction.ImmediateResponse (HTTP 422)
//     replaces the response body. Because the response headers have not yet
//     been committed to the downstream client (BUFFERED mode), status and
//     Content-Type are replaced cleanly.
package wordcountguardrail

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"policy-v2/policy"
)

const (
	guardrailStatus  = 422
	guardrailErrType = "WORD_COUNT_GUARDRAIL"
)

var wordSplitRe = regexp.MustCompile(`\s+`)

// WordCountGuardrailPolicy validates the word count of request and/or response
// bodies against configurable min/max thresholds.
type WordCountGuardrailPolicy struct {
	hasRequest  bool
	reqParams   wordCountParams
	hasResponse bool
	respParams  wordCountParams
}

type wordCountParams struct {
	min              int
	max              int
	jsonPath         string // request: JSONPath to user text; response: path for plain JSON
	streamingJsonPath string // response only: JSONPath applied per SSE event and concatenated
	invert           bool
	showAssessment   bool
}

// Compile-time interface assertions.
var (
	_ policy.RequestBodyPolicy  = (*WordCountGuardrailPolicy)(nil)
	_ policy.ResponseBodyPolicy = (*WordCountGuardrailPolicy)(nil)
)

// GetPolicy constructs a WordCountGuardrailPolicy from the provided parameters.
// All parameter validation happens here — hook methods must not parse params.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &WordCountGuardrailPolicy{}

	if raw, ok := params["request"].(map[string]interface{}); ok {
		rp, err := parseParams(raw)
		if err != nil {
			return nil, fmt.Errorf("request params: %w", err)
		}
		p.hasRequest = true
		p.reqParams = rp
	}

	if raw, ok := params["response"].(map[string]interface{}); ok {
		rp, err := parseParams(raw)
		if err != nil {
			return nil, fmt.Errorf("response params: %w", err)
		}
		p.hasResponse = true
		p.respParams = rp
	}

	if !p.hasRequest && !p.hasResponse {
		return nil, fmt.Errorf("at least one of 'request' or 'response' must be configured")
	}

	slog.Debug("WordCountGuardrail: policy initialised",
		"hasRequest", p.hasRequest,
		"hasResponse", p.hasResponse,
	)
	return p, nil
}

// ─── Request side: buffered ───────────────────────────────────────────────────

// OnRequestBody validates the word count of the fully-buffered request body.
// Returns ImmediateResponse (HTTP 422) if the word count violates the range.
// The request has not yet been forwarded upstream, so ImmediateResponse works.
func (p *WordCountGuardrailPolicy) OnRequestBody(ctx *policy.RequestBodyContext) policy.RequestBodyAction {
	if !p.hasRequest {
		return policy.RequestBodyAction{}
	}
	if ctx.Body == nil || len(ctx.Body.Content) == 0 {
		return policy.RequestBodyAction{}
	}

	text, err := extractRequestText(ctx.Body.Content, p.reqParams.jsonPath)
	if err != nil {
		slog.Debug("WordCountGuardrail: request JSONPath extraction failed",
			"jsonPath", p.reqParams.jsonPath, "error", err)
		return p.rejectRequest(fmt.Sprintf("JSONPath extraction failed: %v", err), p.reqParams)
	}

	passed, wordCount := validate(text, p.reqParams)
	if !passed {
		slog.Debug("WordCountGuardrail: request validation failed",
			"wordCount", wordCount, "min", p.reqParams.min, "max", p.reqParams.max)
		return p.rejectRequest(violationReason(wordCount, p.reqParams), p.reqParams)
	}

	slog.Debug("WordCountGuardrail: request validation passed", "wordCount", wordCount)
	return policy.RequestBodyAction{}
}

// ─── Response side: buffered ──────────────────────────────────────────────────

// OnResponseBody validates the word count of the fully-buffered response body.
//
// The body may be plain JSON (non-streaming upstream) or aggregated SSE events
// (streaming upstream forced into BUFFERED mode by this policy).
// extractResponseText handles both formats, using the configured paths:
//   - Plain JSON → respParams.jsonPath (or full body if empty)
//   - SSE        → respParams.streamingJsonPath applied per event (or auto-extract if empty)
//
// Returns ImmediateResponse (HTTP 422) if the word count violates the range.
// Because we are in BUFFERED mode, response headers have not yet been committed
// to the downstream client — status and Content-Type can be replaced cleanly.
func (p *WordCountGuardrailPolicy) OnResponseBody(ctx *policy.ResponseBodyContext) policy.ResponseBodyAction {
	if !p.hasResponse {
		return policy.ResponseBodyAction{}
	}
	if ctx.ResponseBody == nil || len(ctx.ResponseBody.Content) == 0 {
		return policy.ResponseBodyAction{}
	}

	text, err := extractResponseText(ctx.ResponseBody.Content, p.respParams.jsonPath, p.respParams.streamingJsonPath)
	if err != nil {
		slog.Debug("WordCountGuardrail: response content extraction failed", "error", err)
		return p.rejectResponse(fmt.Sprintf("content extraction failed: %v", err), p.respParams)
	}

	passed, wordCount := validate(text, p.respParams)
	if !passed {
		slog.Debug("WordCountGuardrail: response validation failed",
			"wordCount", wordCount, "min", p.respParams.min, "max", p.respParams.max)
		return p.rejectResponse(violationReason(wordCount, p.respParams), p.respParams)
	}

	slog.Debug("WordCountGuardrail: response validation passed", "wordCount", wordCount)
	return policy.ResponseBodyAction{}
}

// ─── Text extraction ──────────────────────────────────────────────────────────

// extractRequestText extracts the text to validate from a request body.
// Uses nested JSONPath (e.g. "$.messages[0].content") to navigate into the
// JSON document. If jsonPath is empty the entire body is used as a string.
func extractRequestText(body []byte, jsonPath string) (string, error) {
	if jsonPath == "" {
		return strings.TrimSpace(string(body)), nil
	}
	return extractJSONPath(body, jsonPath)
}

// extractResponseText extracts the text to validate from a response body.
//
// Detection logic:
//  1. If the body starts with "data: " it is aggregated SSE.
//     streamingJsonPath (e.g. "$.choices[0].delta.content") is applied to each
//     event and all extracted strings are concatenated.
//     If streamingJsonPath is empty the policy auto-extracts by trying
//     delta.content then message.content per event (covers OpenAI out of the box).
//  2. Otherwise the body is plain JSON.
//     jsonPath (e.g. "$.choices[0].message.content") is used if set;
//     the full body string is used if jsonPath is empty.
func extractResponseText(body []byte, jsonPath, streamingJsonPath string) (string, error) {
	trimmed := strings.TrimSpace(string(body))

	if strings.HasPrefix(trimmed, "data: ") {
		// Aggregated SSE — parse and concatenate content from all events.
		return parseSSEContent(body, streamingJsonPath), nil
	}

	// Plain JSON response.
	if jsonPath != "" {
		return extractJSONPath(body, jsonPath)
	}
	return trimmed, nil
}

// parseSSEContent extracts and concatenates all text content from an aggregated
// SSE body (the result of Envoy buffering a streaming upstream response).
//
// streamingJsonPath controls which field is extracted from each event:
//   - Non-empty: the path is applied to each event's JSON object and the string
//     values are concatenated.  Example: "$.choices[0].delta.content".
//   - Empty: auto-extraction — tries delta.content then message.content per
//     event (covers OpenAI streaming and non-streaming out of the box).
//
//	data: {"choices":[{"delta":{"content":"Hello "}}]}\n\n  → "Hello "
//	data: {"choices":[{"delta":{"content":"world"}}]}\n\n   → "world"
//	data: [DONE]\n\n                                         → skipped
//
// Returns the concatenated content string (empty string if no content found).
func parseSSEContent(body []byte, streamingJsonPath string) string {
	var sb strings.Builder

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" || data == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue // malformed event — skip
		}

		if streamingJsonPath != "" {
			// User-configured path: marshal the event back to bytes and use extractJSONPath.
			eventBytes, err := json.Marshal(event)
			if err != nil {
				continue
			}
			val, err := extractJSONPath(eventBytes, streamingJsonPath)
			if err != nil || val == "" {
				continue
			}
			sb.WriteString(val)
		} else {
			// Auto-extract: try delta.content (streaming) then message.content (non-streaming).
			if content := sseStringAt(event, "choices", 0, "delta", "content"); content != "" {
				sb.WriteString(content)
			} else if content := sseStringAt(event, "choices", 0, "message", "content"); content != "" {
				sb.WriteString(content)
			}
		}
	}

	return sb.String()
}

// sseStringAt navigates choices[index].middle.leaf in a parsed SSE event object
// and returns the string value, or "" if not found or not a string.
//
// This covers the two LLM response shapes:
//
//	streaming:     choices[0].delta.content
//	non-streaming: choices[0].message.content
func sseStringAt(event map[string]interface{}, choicesKey string, index int, middle, leaf string) string {
	choices, ok := event[choicesKey].([]interface{})
	if !ok || index >= len(choices) {
		return ""
	}
	choice, ok := choices[index].(map[string]interface{})
	if !ok {
		return ""
	}
	mid, ok := choice[middle].(map[string]interface{})
	if !ok {
		return ""
	}
	v, _ := mid[leaf].(string)
	return v
}

// ─── Validation ───────────────────────────────────────────────────────────────

// validate counts words in text and checks against the configured range.
// Returns (passed, wordCount). Invert inverts the pass/fail logic.
func validate(text string, p wordCountParams) (bool, int) {
	wordCount := countWords(text)
	inRange := wordCount >= p.min && wordCount <= p.max
	if p.invert {
		return !inRange, wordCount
	}
	return inRange, wordCount
}

// countWords counts non-empty whitespace-delimited tokens.
func countWords(text string) int {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0
	}
	count := 0
	for _, w := range wordSplitRe.Split(text, -1) {
		if w != "" {
			count++
		}
	}
	return count
}

// violationReason builds a human-readable reason string for a word count violation.
func violationReason(wordCount int, p wordCountParams) string {
	if p.invert {
		return fmt.Sprintf("word count %d is within the excluded range %d–%d words", wordCount, p.min, p.max)
	}
	return fmt.Sprintf("word count %d is outside the allowed range %d–%d words", wordCount, p.min, p.max)
}

// ─── Response helpers ─────────────────────────────────────────────────────────

func (p *WordCountGuardrailPolicy) rejectRequest(reason string, params wordCountParams) policy.RequestBodyAction {
	return policy.RequestBodyAction{
		ImmediateResponse: &policy.ImmediateResponse{
			Status:  guardrailStatus,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    buildErrorBody(reason, "REQUEST", params.showAssessment),
		},
	}
}

func (p *WordCountGuardrailPolicy) rejectResponse(reason string, params wordCountParams) policy.ResponseBodyAction {
	return policy.ResponseBodyAction{
		ImmediateResponse: &policy.ImmediateResponse{
			Status:  guardrailStatus,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    buildErrorBody(reason, "RESPONSE", params.showAssessment),
		},
	}
}

// buildErrorBody constructs the JSON error body returned on guardrail violation.
//
//	{
//	  "type": "WORD_COUNT_GUARDRAIL",
//	  "message": {
//	    "action": "GUARDRAIL_INTERVENED",
//	    "interveningGuardrail": "word-count-guardrail",
//	    "actionReason": "...",           // always present
//	    "assessments": "...",            // only when showAssessment=true
//	    "direction": "REQUEST|RESPONSE"
//	  }
//	}
func buildErrorBody(reason, direction string, showAssessment bool) []byte {
	msg := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "word-count-guardrail",
		"actionReason":         "Violation of applied word count constraints detected.",
		"direction":            direction,
	}
	if showAssessment {
		msg["assessments"] = reason
	}
	body, err := json.Marshal(map[string]interface{}{
		"type":    guardrailErrType,
		"message": msg,
	})
	if err != nil {
		return []byte(`{"type":"WORD_COUNT_GUARDRAIL","message":"internal error"}`)
	}
	return body
}

// ─── Nested JSONPath extraction (request side only) ───────────────────────────
//
// JSONPath is used only for the REQUEST side to locate the user text field.
// Supports single-level keys ("$.prompt") and array-indexed paths
// ("$.messages[0].content").
//
// The response side uses format-aware extraction (parseSSEContent / full body)
// instead of JSONPath because:
//   - Non-streaming response:  choices[0].message.content
//   - Streaming response:      choices[0].delta.content  (per SSE event)
//
// A single configurable jsonPath cannot cover both shapes, and requiring
// operators to know which to set would be fragile. Format-aware extraction
// handles both automatically.

// extractJSONPath extracts a string value from a JSON payload at the given path.
// Supports nested paths with array indexing: e.g. "$.messages[0].content".
func extractJSONPath(payload []byte, jsonPath string) (string, error) {
	var doc interface{}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	segs, err := parseSegments(strings.TrimPrefix(jsonPath, "$."))
	if err != nil {
		return "", fmt.Errorf("invalid jsonPath %q: %w", jsonPath, err)
	}

	val, err := walkSegments(doc, segs)
	if err != nil {
		return "", fmt.Errorf("jsonPath %q: %w", jsonPath, err)
	}

	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("jsonPath %q: value is not a string (got %T)", jsonPath, val)
	}
	return s, nil
}

// segment is one navigation step in a dotted JSONPath.
// E.g. "$.messages[0].content" → [{key:"messages",isArray:true,idx:0}, {key:"content"}]
type segment struct {
	key     string
	isArray bool
	idx     int
}

// parseSegments splits a dotted path (without the leading "$.")
// into navigation segments, handling array index notation like "messages[0]".
func parseSegments(path string) ([]segment, error) {
	parts := strings.Split(path, ".")
	segs := make([]segment, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("empty segment in path")
		}
		if bracket := strings.Index(part, "["); bracket >= 0 {
			// Array-indexed segment: "messages[0]"
			key := part[:bracket]
			rest := part[bracket:]
			if !strings.HasSuffix(rest, "]") {
				return nil, fmt.Errorf("malformed array index %q", part)
			}
			idxStr := rest[1 : len(rest)-1]
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 0 {
				return nil, fmt.Errorf("invalid array index %q in %q", idxStr, part)
			}
			segs = append(segs, segment{key: key, isArray: true, idx: idx})
		} else {
			segs = append(segs, segment{key: part})
		}
	}
	return segs, nil
}

// walkSegments navigates a decoded JSON document following the given segments.
func walkSegments(doc interface{}, segs []segment) (interface{}, error) {
	cur := doc
	for _, s := range segs {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("expected object at %q, got %T", s.key, cur)
		}
		v, ok := m[s.key]
		if !ok {
			return nil, fmt.Errorf("key %q not found", s.key)
		}
		if s.isArray {
			arr, ok := v.([]interface{})
			if !ok {
				return nil, fmt.Errorf("expected array at %q, got %T", s.key, v)
			}
			if s.idx >= len(arr) {
				return nil, fmt.Errorf("index %d out of bounds (len=%d) at %q", s.idx, len(arr), s.key)
			}
			cur = arr[s.idx]
		} else {
			cur = v
		}
	}
	return cur, nil
}

// ─── Parameter parsing ────────────────────────────────────────────────────────

func parseParams(raw map[string]interface{}) (wordCountParams, error) {
	var p wordCountParams

	minRaw, ok := raw["min"]
	if !ok {
		return p, fmt.Errorf("'min' is required")
	}
	min, err := toInt(minRaw)
	if err != nil {
		return p, fmt.Errorf("'min': %w", err)
	}
	if min < 0 {
		return p, fmt.Errorf("'min' cannot be negative")
	}
	p.min = min

	maxRaw, ok := raw["max"]
	if !ok {
		return p, fmt.Errorf("'max' is required")
	}
	max, err := toInt(maxRaw)
	if err != nil {
		return p, fmt.Errorf("'max': %w", err)
	}
	if max <= 0 {
		return p, fmt.Errorf("'max' must be > 0")
	}
	if min > max {
		return p, fmt.Errorf("'min' (%d) cannot exceed 'max' (%d)", min, max)
	}
	p.max = max

	if v, ok := raw["jsonPath"]; ok {
		s, ok := v.(string)
		if !ok {
			return p, fmt.Errorf("'jsonPath' must be a string")
		}
		p.jsonPath = s
	}

	if v, ok := raw["streamingJsonPath"]; ok {
		s, ok := v.(string)
		if !ok {
			return p, fmt.Errorf("'streamingJsonPath' must be a string")
		}
		p.streamingJsonPath = s
	}

	if v, ok := raw["invert"]; ok {
		b, ok := v.(bool)
		if !ok {
			return p, fmt.Errorf("'invert' must be a boolean")
		}
		p.invert = b
	}

	if v, ok := raw["showAssessment"]; ok {
		b, ok := v.(bool)
		if !ok {
			return p, fmt.Errorf("'showAssessment' must be a boolean")
		}
		p.showAssessment = b
	}

	return p, nil
}

// toInt converts the JSON-decoded numeric types (float64, int, int64, string)
// to a plain int. json.Unmarshal always produces float64 for numbers.
func toInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != float64(int(n)) {
			return 0, fmt.Errorf("expected integer, got %v", n)
		}
		return int(n), nil
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("cannot parse %q as integer", n)
		}
		return i, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", v)
	}
}
