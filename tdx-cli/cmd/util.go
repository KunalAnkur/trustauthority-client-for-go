/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
)

func parsePolicyIds(policyIds string) ([]uuid.UUID, error) {
	var pIds []uuid.UUID
	if len(policyIds) != 0 {
		Ids := strings.Split(policyIds, ",")
		for _, id := range Ids {
			if uid, err := uuid.Parse(id); err != nil {
				return nil, errors.Errorf("Policy Id:%q is not a valid UUID", id)
			} else {
				pIds = append(pIds, uid)
			}
		}
	}

	return pIds, nil
}

// decodeBase64 decodes standard and URL-safe base64, with or without padding.
// The CLI documents base64|base64url input, and a TD quote read back from a
// file or an HTTP response can arrive in either form.
//
// Line breaks and surrounding whitespace are ignored: base64(1) wraps its
// output at 76 columns unless -w0 is given, and a quote encoded that way would
// otherwise be rejected.
func decodeBase64(encoded string) ([]byte, error) {
	encoded = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, encoded)

	if encoded == "" {
		return nil, errors.New("Value is empty")
	}

	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(encoded); err == nil {
			return decoded, nil
		}
	}

	return nil, errors.New("Value is not valid base64 or base64url")
}

// maxQuoteFileSize caps what readQuoteFile will read. A TD quote is a few KB;
// the Trust Authority rejects request bodies over 500,000 bytes, so anything
// approaching that cannot be attested anyway.
const maxQuoteFileSize = 512 * 1024

// readQuoteFile reads a base64 encoded TD quote from a file and decodes it.
func readQuoteFile(path string) ([]byte, error) {
	quotePath, err := ValidateFilePath(path)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid quote file path provided")
	}

	info, err := os.Stat(quotePath)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading quote file")
	}
	if info.Size() > maxQuoteFileSize {
		return nil, errors.Errorf("Quote file is larger than %d bytes", maxQuoteFileSize)
	}

	contents, err := os.ReadFile(quotePath)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading quote file")
	}

	quote, err := decodeBase64(string(contents))
	if err != nil {
		// A raw quote read straight from configfs-tsm is a common mistake. Say so
		// rather than letting the Trust Authority reject it later.
		if !utf8.Valid(contents) {
			return nil, errors.Errorf("Quote file %q appears to hold a raw binary quote; base64 encode it first, for example: base64 -w0 quote.dat > quote.b64", path)
		}
		return nil, errors.Wrapf(err, "Error while base64 decoding quote file %q", path)
	}

	return quote, nil
}

func ValidateFilePath(path string) (string, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return "", errors.Wrap(ErrInvalidFilePath, "path cannot be directory, please provide file path")
	}
	cleanedPath := filepath.Clean(path)
	if err := checkFilePathForInvalidChars(cleanedPath); err != nil {
		return "", errors.Wrap(ErrInvalidFilePath, err.Error())
	}
	r, err := filepath.EvalSymlinks(cleanedPath)
	if err != nil && !os.IsNotExist(err) {
		return cleanedPath, errors.Wrap(ErrInvalidFilePath, "Unsafe symlink detected in path")
	}
	if r == "" {
		return cleanedPath, nil
	}
	if err = checkFilePathForInvalidChars(r); err != nil {
		return "", errors.Wrap(ErrInvalidFilePath, err.Error())
	}
	return r, nil
}

func checkFilePathForInvalidChars(path string) error {
	filePath, fileName := filepath.Split(path)
	//Max file path length allowed in linux is 4096 characters
	if len(path) > constants.LinuxFilePathSize || !filePathRegex.MatchString(filePath) {
		return errors.New("Invalid file path provided")
	}
	if !fileNameRegex.MatchString(fileName) {
		return errors.New("Invalid file name provided")
	}
	return nil
}
