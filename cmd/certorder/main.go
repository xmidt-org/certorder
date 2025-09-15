// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/xmidt-org/certorder"
)

type Config struct {
	Files  []string `arg:"" help:"Input certificate files or directories." type:"existingfile"`
	Output string   `short:"o" help:"Output bundle file path." type:"path" default:"bundle.p12"`
	Glob   []string `short:"g" help:"Glob patterns for file matching (can be specified multiple times)."`
	Force  bool     `short:"f" help:"Force overwrite existing output file."`
}

func main() {
	var CLI Config

	ctx := kong.Parse(&CLI,
		kong.Name("certorder"),
		kong.Description("A tool for ordering and managing X.509 certificate chains."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))

	err := CLI.Run()
	ctx.FatalIfErrorf(err)
}

func (c *Config) Run() error {
	// Check if output file exists and force flag
	if !c.Force {
		if _, err := os.Stat(c.Output); err == nil {
			return fmt.Errorf("output file %s already exists (use -f to overwrite)", c.Output)
		}
	}

	opts := c.opts()

	// Create bundle
	bundle, err := certorder.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create bundle: %w", err)
	}

	// Create output file
	outFile, err := os.Create(c.Output)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Write bundle
	if err := bundle.Write(outFile); err != nil {
		return fmt.Errorf("failed to write bundle: %w", err)
	}

	// Count certificates
	ordered := bundle.Ordered()
	fmt.Printf("Successfully created certificate bundle: %s (%d certificates)\n", c.Output, len(ordered))

	// Show certificate order
	for i, cert := range ordered {
		certType := "Leaf"
		if cert.IsCA {
			if cert.Subject.String() == cert.Issuer.String() {
				certType = "Root CA"
			} else {
				certType = "Intermediate CA"
			}
		}
		fmt.Printf("  %d. %s (%s)\n", i+1, cert.Subject.CommonName, certType)
	}

	return nil
}

func (c *Config) opts() []certorder.Option {
	opts := make([]certorder.Option, 0, len(c.Files))

	// Add files
	for _, file := range c.Files {
		opts = append(opts, certorder.FromFile(file))
	}

	return opts
}
