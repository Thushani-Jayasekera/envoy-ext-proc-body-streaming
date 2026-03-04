// Package setheaders implements a policy that sets (overwrites) HTTP headers
// on requests to upstream and/or responses to the downstream client.
//
// All parameter parsing happens at GetPolicy time — hook methods do zero
// allocation per request.
//
// Configuration:
//
//	request:
//	  headers:
//	    - name: "X-Forwarded-By"
//	      value: "api-gateway"
//	response:
//	  headers:
//	    - name: "Cache-Control"
//	      value: "no-store"
//
// Legacy flat keys (requestHeaders, responseHeaders) are also accepted.
package setheaders

import (
	"fmt"
	"strings"

	"policy-v2/policy"
)

// SetHeadersPolicy sets pre-configured headers at the request and/or response
// header phase. Implements RequestHeaderPolicy and ResponseHeaderPolicy.
//
// Header mutations live in the header phase hooks (OnRequestHeaders /
// OnResponseHeaders) which return HeaderAction — the correct phase for header
// mutations. This avoids the mistake of trying to modify headers from a body
// phase hook where they may already be committed.
type SetHeadersPolicy struct {
	requestHeaders  map[string]string // lowercase name → value, built at GetPolicy time
	responseHeaders map[string]string
}

// Compile-time interface assertions.
var (
	_ policy.RequestHeaderPolicy  = (*SetHeadersPolicy)(nil)
	_ policy.ResponseHeaderPolicy = (*SetHeadersPolicy)(nil)
)

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	reqHeaders, err := parsePhaseHeaders(params, "request", "requestHeaders")
	if err != nil {
		return nil, fmt.Errorf("request headers: %w", err)
	}
	respHeaders, err := parsePhaseHeaders(params, "response", "responseHeaders")
	if err != nil {
		return nil, fmt.Errorf("response headers: %w", err)
	}
	if len(reqHeaders) == 0 && len(respHeaders) == 0 {
		return nil, fmt.Errorf("at least one of 'request.headers' or 'response.headers' must be specified")
	}
	return &SetHeadersPolicy{
		requestHeaders:  reqHeaders,
		responseHeaders: respHeaders,
	}, nil
}

// OnRequestHeaders sets pre-configured headers on the outgoing request.
// Returns HeaderAction{} (pass-through) if no request headers are configured.
func (p *SetHeadersPolicy) OnRequestHeaders(_ *policy.RequestHeaderContext) policy.HeaderAction {
	if len(p.requestHeaders) == 0 {
		return policy.HeaderAction{}
	}
	return policy.HeaderAction{Set: p.requestHeaders}
}

// OnResponseHeaders sets pre-configured headers on the response to the client.
// Returns HeaderAction{} (pass-through) if no response headers are configured.
func (p *SetHeadersPolicy) OnResponseHeaders(_ *policy.ResponseHeaderContext) policy.HeaderAction {
	if len(p.responseHeaders) == 0 {
		return policy.HeaderAction{}
	}
	return policy.HeaderAction{Set: p.responseHeaders}
}

// ─── Parameter parsing ────────────────────────────────────────────────────────

func parsePhaseHeaders(params map[string]interface{}, phaseKey, legacyKey string) (map[string]string, error) {
	raw, present := resolvePhaseRaw(params, phaseKey, legacyKey)
	if !present {
		return nil, nil
	}

	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s.headers' must be an array", phaseKey)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("'%s.headers' cannot be empty", phaseKey)
	}

	result := make(map[string]string, len(items))
	for i, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s.headers[%d] must be an object", phaseKey, i)
		}

		name, err := requireStringField(m, "name", fmt.Sprintf("%s.headers[%d]", phaseKey, i))
		if err != nil {
			return nil, err
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return nil, fmt.Errorf("%s.headers[%d].name cannot be blank", phaseKey, i)
		}

		value, err := requireStringField(m, "value", fmt.Sprintf("%s.headers[%d]", phaseKey, i))
		if err != nil {
			return nil, err
		}

		result[name] = value // last definition wins for duplicate names
	}
	return result, nil
}

func resolvePhaseRaw(params map[string]interface{}, phaseKey, legacyKey string) (interface{}, bool) {
	if phaseRaw, ok := params[phaseKey]; ok {
		phaseMap, ok := phaseRaw.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, ok := phaseMap["headers"]
		return v, ok
	}
	if v, ok := params[legacyKey]; ok {
		return v, true
	}
	return nil, false
}

func requireStringField(m map[string]interface{}, field, prefix string) (string, error) {
	v, ok := m[field]
	if !ok {
		return "", fmt.Errorf("%s missing required field '%s'", prefix, field)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s.%s must be a string", prefix, field)
	}
	return s, nil
}
