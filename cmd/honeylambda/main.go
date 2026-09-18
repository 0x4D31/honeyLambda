// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/0x4D31/honeyLambda/v2/internal/trap"
)

var version = "2.0.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: honeylambda <serve|check|bundle|token|version> [options]")
	}
	command := args[0]
	if command == "version" || command == "token" {
		if len(args) != 1 {
			return errors.New("command takes no arguments")
		}
		if command == "version" {
			fmt.Println(version)
			return nil
		}
		id, err := trap.RandomID()
		if err == nil {
			fmt.Println(id)
		}
		return err
	}
	if command != "serve" && command != "check" && command != "bundle" {
		return fmt.Errorf("unknown command %q", command)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := flags.String("config", envOr("HONEY_CONFIG", "config.json"), "JSON configuration file")
	var listen *string
	var out *string
	if command == "bundle" {
		out = flags.String("out", "", "new directory for portable config and response assets")
	}
	if command == "serve" {
		listen = flags.String("listen", "", "listen address (default :PORT, or :8080)")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if out != nil && *out == "" {
		return errors.New("bundle requires -out DIRECTORY")
	}
	c, err := trap.Load(*configPath)
	if err != nil {
		return err
	}
	if command == "check" {
		fmt.Fprintln(os.Stderr, "configuration valid")
		return nil
	}
	if command == "bundle" {
		files, err := c.Bundle()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
			return err
		}
		if err := os.Mkdir(*out, 0755); err != nil {
			return fmt.Errorf("create bundle directory (must not exist): %w", err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(*out, name), data, 0644); err != nil {
				return err
			}
		}
		return nil
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	h, err := trap.New(c, os.Stdout, log)
	if err != nil {
		return err
	}
	if *listen == "" {
		port := envOr("PORT", "8080")
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("PORT must be between 1 and 65535")
		}
		*listen = ":" + port
	}
	server := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
