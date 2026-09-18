// SPDX-License-Identifier: GPL-3.0-or-later
package trap

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// Bundle packages an already validated configuration and its snapshotted assets.
// It does not resolve alert credentials or retain paths outside the bundle.
// Content-addressed files deduplicate bodies and preserve the JSON size limit.
func (c *Config) Bundle() (map[string][]byte, error) {
	files := make(map[string][]byte)
	response := func(r Response) Response {
		r.Body, r.BodyBase64, r.BodyFile = "", "", ""
		if len(r.data) != 0 {
			r.BodyFile = fmt.Sprintf("%x.body", sha256.Sum256(r.data))
			files[r.BodyFile] = append([]byte(nil), r.data...)
		}
		return r
	}
	copy := *c
	copy.DefaultResponse = response(c.DefaultResponse)
	copy.Tokens = append([]Token(nil), c.Tokens...)
	for i := range copy.Tokens {
		if copy.Tokens[i].Response != nil {
			r := response(*copy.Tokens[i].Response)
			copy.Tokens[i].Response = &r
		}
	}
	b, err := json.Marshal(copy)
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigBytes {
		return nil, fmt.Errorf("bundled config exceeds %d bytes", maxConfigBytes)
	}
	files["config.json"] = b
	return files, nil
}
