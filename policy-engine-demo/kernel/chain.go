// Package kernel implements the policy engine kernel for the demo.
// It replicates the behaviour of the api-platform policy engine using the
// policy-v2 interface design (type-assertion capability detection instead of Mode()).
package kernel

import "policy-v2/policy"

// PolicyChain holds the policies for one route and pre-computed capability flags.
// Flags are set once at BuildChain time via type-assertions — zero per-request cost.
type PolicyChain struct {
	Policies []policy.Policy

	// Header phase capabilities.
	HasRequestHeader  bool
	HasResponseHeader bool

	// Request body capabilities.
	HasRequestBody    bool // any policy processes the request body
	StreamRequestBody bool // true only when ALL request-body policies support streaming

	// Response body capabilities.
	HasResponseBody    bool // any policy processes the response body
	StreamResponseBody bool // true only when ALL response-body policies support streaming
}

// BuildChain inspects each policy via type assertions and returns a PolicyChain
// with all capability flags pre-computed.
//
// Mode selection rules (mirrors api-platform/sdk interface.go):
//   - If ALL response-body policies implement StreamingResponseBodyPolicy → StreamResponseBody=true
//     (kernel will use FULL_DUPLEX_STREAMED when upstream is also streaming)
//   - If ANY response-body policy is buffered-only → StreamResponseBody=false
//     (kernel forces BUFFERED regardless of upstream streaming behaviour)
func BuildChain(policies []policy.Policy) *PolicyChain {
	c := &PolicyChain{Policies: policies}
	if len(policies) == 0 {
		return c
	}

	// Track whether all body-capable policies support streaming.
	allReqStreaming := true
	allRespStreaming := true

	for _, p := range policies {
		if _, ok := p.(policy.RequestHeaderPolicy); ok {
			c.HasRequestHeader = true
		}
		if _, ok := p.(policy.ResponseHeaderPolicy); ok {
			c.HasResponseHeader = true
		}

		// Request body: check streaming variant first (it also satisfies RequestBodyPolicy).
		if _, ok := p.(policy.StreamingRequestBodyPolicy); ok {
			c.HasRequestBody = true
			// streaming policy: does not block stream mode
		} else if _, ok := p.(policy.RequestBodyPolicy); ok {
			c.HasRequestBody = true
			allReqStreaming = false // buffered-only: prevents FDS on request side
		}

		// Response body: same pattern.
		if _, ok := p.(policy.StreamingResponseBodyPolicy); ok {
			c.HasResponseBody = true
		} else if _, ok := p.(policy.ResponseBodyPolicy); ok {
			c.HasResponseBody = true
			allRespStreaming = false
		}
	}

	if c.HasRequestBody && allReqStreaming {
		c.StreamRequestBody = true
	}
	if c.HasResponseBody && allRespStreaming {
		c.StreamResponseBody = true
	}

	return c
}
