// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/0x4D31/honeyLambda/v2/internal/trap"
)

func initConfig(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	out := flags.String("out", "config.json", "new configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	value, err := trap.RandomID()
	if err != nil {
		return err
	}
	config := trap.Config{Version: 2, DefaultResponse: trap.Response{Status: 404, Body: "Not found\n"}, Tokens: []trap.Token{{ID: "first-token", Path: "/t/" + value, Response: &trap.Response{Status: 200, Body: "OK\n"}}}}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		_ = os.Remove(*out)
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "created", *out)
	return nil
}

func tokenURLs(c *trap.Config, endpoint string) (map[string]string, error) {
	base, err := url.Parse(endpoint)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || base.Opaque != "" {
		return nil, errors.New("endpoint must be an HTTP(S) base URL without userinfo, query or fragment")
	}
	result := make(map[string]string, len(c.Tokens))
	for _, token := range c.Tokens {
		q := url.Values{}
		for key, value := range token.Query {
			q.Set(key, value)
		}
		target := strings.TrimSuffix(endpoint, "/") + token.Path
		if query := q.Encode(); query != "" {
			target += "?" + query
		}
		result[token.ID] = target
	}
	return result, nil
}
