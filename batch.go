package attestly

import (
	"errors"
	"runtime"
	"sync"
)

// BatchResult reports the outcome of verifying one attestation in a batch.
type BatchResult struct {
	// Index is the position in the input slice.
	Index int
	// Err is nil when the attestation verified.
	Err error
}

// OK reports whether this one verified.
func (r BatchResult) OK() bool { return r.Err == nil }

// BatchSummary counts outcomes by kind.
//
// The split matters operationally: a batch that is 5% expired means a stale
// cache, while a batch that is 5% forged means someone is attacking you. A
// single "failed" count cannot tell you which day you are having.
type BatchSummary struct {
	Total      int
	Verified   int
	Expired    int
	BadSig     int
	UnknownKey int
	Other      int
}

// AllVerified reports whether every attestation passed.
func (s BatchSummary) AllVerified() bool { return s.Total > 0 && s.Verified == s.Total }

// VerifyBatch verifies many attestations against one key ring, concurrently.
//
// It never stops early. A caller verifying a page of results wants to know
// about every bad one, not just the first — stopping early would hide the
// pattern that says whether this is staleness or an attack.
//
// Results are returned in input order regardless of completion order.
func VerifyBatch(atts []*Attestation, ring *KeyRing, opts ...VerifyOption) ([]BatchResult, BatchSummary) {
	results := make([]BatchResult, len(atts))
	if len(atts) == 0 {
		return results, BatchSummary{}
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > len(atts) {
		workers = len(atts)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = BatchResult{Index: i, Err: VerifyWithRing(atts[i], ring, opts...)}
			}
		}()
	}
	for i := range atts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results, Summarize(results)
}

// Summarize counts results by failure kind.
func Summarize(results []BatchResult) BatchSummary {
	s := BatchSummary{Total: len(results)}
	for _, r := range results {
		switch {
		case r.Err == nil:
			s.Verified++
		case errors.Is(r.Err, ErrExpired), errors.Is(r.Err, ErrNotYetValid):
			s.Expired++
		case errors.Is(r.Err, ErrBadSignature):
			s.BadSig++
		case errors.Is(r.Err, ErrUnknownKeyID), errors.Is(r.Err, ErrKeyRetired):
			s.UnknownKey++
		default:
			s.Other++
		}
	}
	return s
}

// Failures returns only the results that did not verify.
func Failures(results []BatchResult) []BatchResult {
	var out []BatchResult
	for _, r := range results {
		if r.Err != nil {
			out = append(out, r)
		}
	}
	return out
}
