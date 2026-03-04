package policy

import "bytes"

// ─── Buffering utility functions ──────────────────────────────────────────────
//
// Call these from your NeedsMoreData implementation instead of writing the
// logic yourself. They can be composed for multi-condition strategies.

// NeedsMoreDataSSE returns true until a complete SSE event boundary (\n\n) is
// present in the accumulated data. Use this for OpenAI / Anthropic / Mistral
// style SSE streams to flush exactly one logical event per chunk handler call.
//
//	func (p *MyPolicy) NeedsMoreData(accumulated []byte, eos bool) bool {
//	    return policy.NeedsMoreDataSSE(accumulated, eos)
//	}
func NeedsMoreDataSSE(accumulated []byte, eos bool) bool {
	return !bytes.Contains(accumulated, []byte("\n\n"))
}

// NeedsMoreDataDelimiter returns true until any of the given delimiter bytes
// appears in the accumulated data. Use for newline-delimited formats (NDJSON,
// plain newline-separated text, etc.).
//
//	func (p *MyPolicy) NeedsMoreData(accumulated []byte, eos bool) bool {
//	    return policy.NeedsMoreDataDelimiter(accumulated, eos, '\n')
//	}
func NeedsMoreDataDelimiter(accumulated []byte, eos bool, delimiters ...byte) bool {
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
//	func (p *MyPolicy) NeedsMoreData(accumulated []byte, eos bool) bool {
//	    return policy.NeedsMoreDataTokenBudget(accumulated, eos, 50, countTokens)
//	}
func NeedsMoreDataTokenBudget(accumulated []byte, eos bool, minTokens int, countFunc func([]byte) int) bool {
	return countFunc(accumulated) < minTokens
}
