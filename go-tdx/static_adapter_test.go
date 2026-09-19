/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"encoding/json"
	"testing"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/stretchr/testify/assert"
)

func TestNewStaticEvidenceAdapter(t *testing.T) {
	adapter, err := NewStaticEvidenceAdapter([]byte{0x01, 0x02, 0x03})
	assert.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, "tdx", adapter.GetEvidenceIdentifier())
}

func TestNewStaticEvidenceAdapterEmptyQuote(t *testing.T) {
	for _, quote := range [][]byte{nil, {}} {
		adapter, err := NewStaticEvidenceAdapter(quote)
		assert.Error(t, err)
		assert.Nil(t, adapter)
	}
}

func TestStaticAdapterGetEvidence(t *testing.T) {
	quote := []byte{0xde, 0xad, 0xbe, 0xef}

	adapter, err := NewStaticEvidenceAdapter(quote)
	assert.NoError(t, err)

	evidence, err := adapter.GetEvidence(nil, nil)
	assert.NoError(t, err)

	static, ok := evidence.(*staticTdxEvidence)
	assert.True(t, ok)
	assert.Equal(t, quote, static.Quote)
}

// The request body must be exactly {"quote": "..."}. A "runtime_data": null
// would make the Trust Authority appraise report data that was never bound.
func TestStaticAdapterEvidenceSerialization(t *testing.T) {
	adapter, err := NewStaticEvidenceAdapter([]byte{0xde, 0xad, 0xbe, 0xef})
	assert.NoError(t, err)

	evidence, err := adapter.GetEvidence(nil, nil)
	assert.NoError(t, err)

	body, err := json.Marshal(evidence)
	assert.NoError(t, err)
	assert.JSONEq(t, `{"quote":"3q2+7w=="}`, string(body))
}

// A nonce obtained here would be unrelated to a quote that already exists, so
// the adapter refuses rather than send evidence the Trust Authority will reject.
func TestStaticAdapterRejectsVerifierNonce(t *testing.T) {
	adapter, err := NewStaticEvidenceAdapter([]byte{0xde, 0xad, 0xbe, 0xef})
	assert.NoError(t, err)

	evidence, err := adapter.GetEvidence(&connector.VerifierNonce{}, nil)
	assert.Error(t, err)
	assert.Nil(t, evidence)
}

// User data the quote was collected against is passed through as runtime_data,
// for the Trust Authority to check against REPORTDATA.
func TestStaticAdapterPassesThroughUserData(t *testing.T) {
	userData := []byte("user data")

	adapter, err := NewStaticEvidenceAdapter([]byte{0xde, 0xad, 0xbe, 0xef})
	assert.NoError(t, err)

	evidence, err := adapter.GetEvidence(nil, userData)
	assert.NoError(t, err)

	static, ok := evidence.(*staticTdxEvidence)
	assert.True(t, ok)
	assert.Equal(t, userData, static.RuntimeData)

	body, err := json.Marshal(evidence)
	assert.NoError(t, err)
	assert.JSONEq(t, `{"quote":"3q2+7w==","runtime_data":"dXNlciBkYXRh"}`, string(body))
}
