// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"log/slog"
	"os"

	"github.com/0x4D31/honeyLambda/v2/internal/lambdahttp"
	"github.com/0x4D31/honeyLambda/v2/internal/trap"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	path := os.Getenv("HONEY_CONFIG")
	if path == "" {
		path = "config/config.json"
	}
	c, err := trap.Load(path)
	if err != nil {
		log.Error("configuration_failed", "reason", err.Error())
		os.Exit(1)
	}
	options, err := trap.RemoteOptionsFromEnv()
	if err != nil {
		log.Error("configuration_failed", "reason", err.Error())
		os.Exit(1)
	}
	h, err := trap.NewReceiver(c, options, os.Stdout, log)
	if err != nil {
		log.Error("configuration_failed", "reason", err.Error())
		os.Exit(1)
	}
	lambda.Start(lambdahttp.Handler(h))
}
