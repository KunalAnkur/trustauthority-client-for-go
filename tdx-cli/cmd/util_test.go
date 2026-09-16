/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeBase64(t *testing.T) {
	quote := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03}

	tt := []struct {
		encoded     string
		wantErr     bool
		description string
	}{
		{base64.StdEncoding.EncodeToString(quote), false, "standard encoding"},
		{base64.RawStdEncoding.EncodeToString(quote), false, "standard encoding without padding"},
		{base64.URLEncoding.EncodeToString(quote), false, "url encoding"},
		{base64.RawURLEncoding.EncodeToString(quote), false, "url encoding without padding"},
		// base64(1) wraps at 76 columns unless -w0 is used
		{"3q2+\n7wEC\nAw==", false, "wrapped across lines"},
		{"  " + base64.StdEncoding.EncodeToString(quote) + "\n", false, "surrounding whitespace"},
		{"not!valid!base64", true, "invalid characters"},
		{"", true, "empty value"},
		{"   \n\t ", true, "whitespace only"},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			decoded, err := decodeBase64(tc.encoded)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, decoded)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, quote, decoded)
		})
	}
}
