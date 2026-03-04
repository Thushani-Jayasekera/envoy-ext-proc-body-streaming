package policy

import "bytes"

// ─── Buffering utility functions ──────────────────────────────────────────────
//
// Call these from your NeedsMoreData implementation instead of writing the
// logic yourself. They can be composed for multi-condition strategies.
//
// Note: NeedsMoreData is never called by the kernel when eos=true — the kernel
// flushes unconditionally on the final chunk. There is no need to handle eos
// inside these helpers or in your NeedsMoreData implementation.

// NeedsMoreDataSSE returns true until a complete SSE event boundary (\n\n) is
// present in the accumulated data. Use this for OpenAI / Anthropic / Mistral
// style SSE streams to flush exactly one logical event per chunk handler call.
//
//	func (p *MyPolicy) NeedsMoreData(accumulated []byte) bool {
//	    return policy.NeedsMoreDataSSE(accumulated)
//	}
func NeedsMoreDataSSE(accumulated []byte) bool {
	return !bytes.Contains(accumulated, []byte("\n\n"))
}

// NeedsMoreDataDelimiter returns true until any of the given delimiter bytes
// appears in the accumulated data. Use for newline-delimited formats (NDJSON,
// plain newline-separated text, etc.).
//
//	func (p *MyPolicy) NeedsMoreData(accumulated []byte) bool {
//	    return policy.NeedsMoreDataDelimiter(accumulated, '\n')
//	}
func NeedsMoreDataDelimiter(accumulated []byte, delimiters ...byte) bool {
	for _, d := range delimiters {
		if bytes.LastIndexByte(accumulated, d) >= 0 {
			return false
		}
	}
	return true
}

// NeedsMoreDataTokenBudget returns true until countFunc reports that at least
// minTokens tokens have accumulated. Use when your policy needs a minimum
// token context window before it can make a decision.
//
//	func (p *MyPolicy) NeedsMoreData(accumulated []byte) bool {
//	    return policy.NeedsMoreDataTokenBudget(accumulated, 50, countTokens)
//	}
func NeedsMoreDataTokenBudget(accumulated []byte, minTokens int, countFunc func([]byte) int) bool {
	return countFunc(accumulated) < minTokens
}
