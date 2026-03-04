package kernel

import (
	"fmt"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"policy-v2/policy"
)

// headerActionToCommonResponse converts a v2 HeaderAction to a CommonResponse
// suitable for use in HeadersResponse.
func headerActionToCommonResponse(action policy.HeaderAction) *extprocv3.CommonResponse {
	hm := headerActionToHeaderMutation(&action)
	if hm == nil {
		return &extprocv3.CommonResponse{}
	}
	return &extprocv3.CommonResponse{HeaderMutation: hm}
}

// headerActionToHeaderMutation converts a v2 HeaderAction to a proto HeaderMutation.
// Returns nil if there are no mutations.
func headerActionToHeaderMutation(action *policy.HeaderAction) *extprocv3.HeaderMutation {
	if action == nil {
		return nil
	}
	if len(action.Set) == 0 && len(action.Remove) == 0 && len(action.Append) == 0 {
		return nil
	}
	hm := &extprocv3.HeaderMutation{}
	for k, v := range action.Set {
		hm.SetHeaders = append(hm.SetHeaders, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: strings.ToLower(k), RawValue: []byte(v)},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	for k, vals := range action.Append {
		for _, v := range vals {
			hm.SetHeaders = append(hm.SetHeaders, &corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: strings.ToLower(k), RawValue: []byte(v)},
				AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
			})
		}
	}
	hm.RemoveHeaders = append(hm.RemoveHeaders, action.Remove...)
	return hm
}

// mergeIntoHeaderMutation appends mutations from a HeaderAction into an existing HeaderMutation.
func mergeIntoHeaderMutation(dst *extprocv3.HeaderMutation, src *policy.HeaderAction) {
	if src == nil {
		return
	}
	for k, v := range src.Set {
		dst.SetHeaders = append(dst.SetHeaders, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: strings.ToLower(k), RawValue: []byte(v)},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	dst.RemoveHeaders = append(dst.RemoveHeaders, src.Remove...)
}

// buildHeaderMutation creates a HeaderMutation from a flat map (for ImmediateResponse headers).
func buildHeaderMutation(headers map[string]string) *extprocv3.HeaderMutation {
	if len(headers) == 0 {
		return nil
	}
	hm := &extprocv3.HeaderMutation{}
	for k, v := range headers {
		hm.SetHeaders = append(hm.SetHeaders, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: strings.ToLower(k), RawValue: []byte(v)},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return hm
}

// buildContentLengthMutation returns a HeaderMutation that sets content-length.
func buildContentLengthMutation(bodyLen int) *extprocv3.HeaderMutation {
	return &extprocv3.HeaderMutation{
		SetHeaders: []*corev3.HeaderValueOption{
			{
				Header:       &corev3.HeaderValue{Key: "content-length", RawValue: []byte(fmt.Sprintf("%d", bodyLen))},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
		},
	}
}
