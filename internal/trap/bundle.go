// SPDX-License-Identifier: GPL-3.0-or-later
package trap

import (
	"crypto/sha256"
	"encoding/base64"
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
	copy := c.withResponses(response)
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

// Export returns a self-contained JSON snapshot for HTTPS distribution.
// The normal 4 MiB document limit also applies after base64 encoding assets.
func (c *Config) Export() ([]byte, error) {
	copy := c.withResponses(func(r Response) Response {
		r.Body, r.BodyFile, r.BodyBase64 = "", "", ""
		if len(r.data) > 0 {
			r.BodyBase64 = base64.StdEncoding.EncodeToString(r.data)
		}
		return r
	})
	data, err := json.Marshal(copy)
	if err == nil && len(data)+1 > maxConfigBytes {
		return nil, fmt.Errorf("exported config exceeds %d bytes", maxConfigBytes)
	}
	return data, err
}

func (c *Config) withResponses(convert func(Response) Response) Config {
	copy := *c
	copy.Schema = ""
	copy.DefaultResponse = convert(c.DefaultResponse)
	copy.Responses = make(map[string]*Response, len(c.Responses))
	for name, response := range c.Responses {
		r := convert(*response)
		copy.Responses[name] = &r
	}
	copy.Tokens = append([]Token(nil), c.Tokens...)
	for i := range copy.Tokens {
		if copy.Tokens[i].Response != nil {
			r := convert(*copy.Tokens[i].Response)
			copy.Tokens[i].Response = &r
		}
	}
	return copy
}

// A content revision is independent of local asset paths, formatting and key order.
func (c *Config) revision() string {
	canonical := c.withResponses(func(r Response) Response {
		r.Body, r.BodyBase64, r.BodyFile = "", "", ""
		if len(r.data) > 0 {
			r.BodyFile = fmt.Sprintf("%x", sha256.Sum256(r.data))
		}
		return r
	})
	canonical.Schema = ""
	data, _ := json.Marshal(canonical) // Config contains only JSON-native fields.
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
