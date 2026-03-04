// policy-engine-demo is a self-contained demonstration of the policy-v2 kernel.
//
// It wires three demo policies:
//
//	Route "openai-chat"       → [pii-masking-regex]    (buffered request + streaming response)
//	Route "openai-guarded"    → [word-count-guardrail] (buffered request + buffered response)
//	Route "httpbin-test"      → [set-headers]          (header mutation only)
//
// Run with:
//
//	go run . [-port 9002]
//
// Point your Envoy config at this server (see envoy-policy-demo.yaml).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"policy-engine-demo/kernel"

	piimaskingregex "policy-v2/policies/pii-masking"
	setheaders "policy-v2/policies/set-headers"
	wordcountguardrail "policy-v2/policies/word-count-guardrail"
	"policy-v2/policy"
)

func main() {
	port := flag.Int("port", 9002, "gRPC listening port")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	k := kernel.NewKernel()
	if err := registerRoutes(k); err != nil {
		slog.Error("Failed to register routes", "error", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf(":%d", *port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("Failed to listen", "addr", addr, "error", err)
		os.Exit(1)
	}

	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(50*1024*1024),
		grpc.MaxSendMsgSize(50*1024*1024),
	)
	extprocv3.RegisterExternalProcessorServer(gs, kernel.NewServer(k))

	slog.Info("policy-engine-demo listening", "addr", addr)
	if err := gs.Serve(lis); err != nil {
		slog.Error("gRPC server failed", "error", err)
		os.Exit(1)
	}
}

// registerRoutes builds PolicyChains for each demo route and registers them.
func registerRoutes(k *kernel.Kernel) error {
	// ── openai-chat: PII masking ───────────────────────────────────────────────
	// Masks email addresses in the request prompt and restores placeholders in the
	// streaming SSE response (OpenAI / Anthropic style).
	//
	// NeedsMoreData: token budget (7) + sentence boundary (.) + custom keyword ("attack").
	// In practice you'd use NeedsMoreDataSSE for SSE streams.
	piiPolicy, err := piimaskingregex.GetPolicy(
		policy.PolicyMetadata{
			RouteName:  "openai-chat",
			APIName:    "openai",
			APIVersion: "v1",
			AttachedTo: policy.LevelRoute,
		},
		map[string]interface{}{
			// No jsonPath: scan the entire request body for PII.
			// The policy supports single-level JSONPath (e.g. "$.prompt") but not
			// nested paths like "$.messages[0].content", so we scan the full body.
			"piiEntities": []interface{}{
				map[string]interface{}{
					"piiEntity": "EMAIL",
					"piiRegex":  `\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`,
				},
				map[string]interface{}{
					"piiEntity": "PHONE",
					"piiRegex":  `\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b`,
				},
			},
			"redactPII": false, // mask mode: placeholders restored in response
		},
	)
	if err != nil {
		return fmt.Errorf("pii-masking policy: %w", err)
	}

	openaiChain := kernel.BuildChain([]policy.Policy{piiPolicy})
	slog.Info("Route registered",
		"route", "openai-chat",
		"policies", len(openaiChain.Policies),
		"HasRequestBody", openaiChain.HasRequestBody,
		"HasResponseBody", openaiChain.HasResponseBody,
		"StreamResponseBody", openaiChain.StreamResponseBody,
	)
	k.RegisterRoute("openai-chat", openaiChain)

	// ── httpbin-test: set-headers ──────────────────────────────────────────────
	// Adds X-Demo-Request on outgoing requests and X-Demo-Response on responses.
	headersPolicy, err := setheaders.GetPolicy(
		policy.PolicyMetadata{
			RouteName:  "httpbin-test",
			APIName:    "httpbin",
			APIVersion: "v1",
			AttachedTo: policy.LevelRoute,
		},
		map[string]interface{}{
			"request": map[string]interface{}{
				"headers": []interface{}{
					map[string]interface{}{"name": "X-Demo-Request", "value": "policy-engine-demo"},
				},
			},
			"response": map[string]interface{}{
				"headers": []interface{}{
					map[string]interface{}{"name": "X-Demo-Response", "value": "policy-engine-demo"},
				},
			},
		},
	)
	if err != nil {
		return fmt.Errorf("set-headers policy: %w", err)
	}

	httpbinChain := kernel.BuildChain([]policy.Policy{headersPolicy})
	slog.Info("Route registered",
		"route", "httpbin-test",
		"policies", len(httpbinChain.Policies),
		"HasRequestHeader", httpbinChain.HasRequestHeader,
		"HasResponseHeader", httpbinChain.HasResponseHeader,
	)
	k.RegisterRoute("httpbin-test", httpbinChain)

	// ── openai-guarded: word count guardrail ───────────────────────────────────
	// Enforces that the request prompt is between 5 and 200 words, and that the
	// complete LLM response is between 10 and 1000 words.
	//
	// Response side: ResponseBodyPolicy only (forces BUFFERED for response body).
	// For streaming upstreams Envoy assembles all SSE chunks before ext_proc sees
	// the body.  parseSSEContent extracts and concatenates all delta.content tokens
	// automatically — no response jsonPath required.
	wcPolicy, err := wordcountguardrail.GetPolicy(
		policy.PolicyMetadata{
			RouteName:  "openai-guarded",
			APIName:    "openai",
			APIVersion: "v1",
			AttachedTo: policy.LevelRoute,
		},
		map[string]interface{}{
			"request": map[string]interface{}{
				"min":            5,
				"max":            200,
				"jsonPath":       "$.messages[0].content",
				"showAssessment": true,
			},
			"response": map[string]interface{}{
				"min":            10,
				"max":            1000,
				// jsonPath: path used when upstream returns plain JSON (stream:false).
				"jsonPath": "$.choices[0].message.content",
				// streamingJsonPath: path applied per SSE event when upstream streams (stream:true).
				// Both default to empty → auto-extraction (tries delta.content then message.content).
				"streamingJsonPath": "$.choices[0].delta.content",
				"showAssessment":    true,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("word-count-guardrail policy: %w", err)
	}

	guardedChain := kernel.BuildChain([]policy.Policy{wcPolicy})
	slog.Info("Route registered",
		"route", "openai-guarded",
		"policies", len(guardedChain.Policies),
		"HasRequestBody", guardedChain.HasRequestBody,
		"HasResponseBody", guardedChain.HasResponseBody,
		"StreamResponseBody", guardedChain.StreamResponseBody,
	)
	k.RegisterRoute("openai-guarded", guardedChain)

	return nil
}
