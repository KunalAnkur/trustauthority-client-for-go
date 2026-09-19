/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

// staticAdapter is a CompositeEvidenceAdapter that returns a TD quote that was
// collected elsewhere, instead of generating one from the local platform.
//
// It exists so that a quote produced inside a TD can be attested from a host
// that has no TEE of its own - for example a relying party performing
// background-check attestation, or an orchestration host that received a quote
// from a confidential workload.
type staticAdapter struct {
	quote []byte
}

// staticTdxEvidence is deliberately not compositeTdxEvidence: that struct tags
// RuntimeData without omitempty, so reusing it would put "runtime_data": null
// on the wire when no user data is supplied.
type staticTdxEvidence struct {
	Quote       []byte `json:"quote"`
	RuntimeData []byte `json:"runtime_data,omitempty"`
}

// NewStaticEvidenceAdapter returns a CompositeEvidenceAdapter that attests the
// supplied TD quote rather than collecting evidence from the local platform.
//
// Because the quote already exists, its REPORTDATA is fixed and nothing can be
// bound into it here. User data may still be passed through when the quote was
// collected against it, i.e. with REPORTDATA already set to SHA512(user_data).
// The adapter cannot check that; the Trust Authority recomputes REPORTDATA and
// rejects a mismatch.
//
// A verifier nonce is rejected: one obtained here would be unrelated to the
// quote, and one the quote was collected against has no way in.
func NewStaticEvidenceAdapter(quote []byte) (connector.CompositeEvidenceAdapter, error) {
	if len(quote) == 0 {
		return nil, errors.New("The quote must not be empty")
	}

	return &staticAdapter{quote: quote}, nil
}

func (adapter *staticAdapter) GetEvidenceIdentifier() string {
	return "tdx"
}

func (adapter *staticAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	if verifierNonce != nil {
		return nil, errors.New("A verifier nonce cannot be bound to a quote that has already been collected")
	}

	return &staticTdxEvidence{
		Quote:       adapter.quote,
		RuntimeData: userData,
	}, nil
}
