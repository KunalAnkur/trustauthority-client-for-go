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
// on the wire. This produces exactly {"quote": "..."}.
type staticTdxEvidence struct {
	Quote []byte `json:"quote"`
}

// NewStaticEvidenceAdapter returns a CompositeEvidenceAdapter that attests the
// supplied TD quote rather than collecting evidence from the local platform.
//
// Because the quote already exists, its REPORTDATA is fixed and nothing can be
// bound into it after the fact. GetEvidence therefore rejects a verifier nonce
// or user data: the Trust Authority recomputes REPORTDATA from those values and
// would reject the quote. Callers that need nonce binding must generate the
// quote with the nonce already hashed into REPORTDATA.
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

	if len(userData) != 0 {
		return nil, errors.New("User data cannot be bound to a quote that has already been collected")
	}

	return &staticTdxEvidence{
		Quote: adapter.quote,
	}, nil
}
