// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package certorder provides functionality for ordering and bundling X.509 certificates
// into a proper certificate chain for use in TLS configurations.
package certorder

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// Bundle represents a collection of certificates that can be ordered into a proper chain.
// It maintains both the certificates and a mapping of certificates to their source files.
type Bundle struct {
	certs  []*x509.Certificate
	logger *zap.Logger
}

type Option func(*Bundle) error

// WithLogger sets the logger for the bundle.
func WithLogger(logger *zap.Logger) Option {
	return func(b *Bundle) error {
		if logger != nil {
			b.logger = logger
		} else {
			b.logger = zap.NewNop()
		}
		return nil
	}
}

// FromFile loads a certificate bundle from the specified file.
func FromFile(file string, errIfNoCerts ...bool) Option {
	return func(b *Bundle) error {
		dir := filepath.Dir(file)
		base := filepath.Base(file)

		fsys := os.DirFS(dir)
		f, err := fsys.Open(base)
		if err != nil {
			return err
		}

		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			return err
		}

		certs, err := parsePEMCertificates(data)
		if err != nil {
			return err
		}

		errIfNoCerts = append(errIfNoCerts, true)

		if len(certs) == 0 && errIfNoCerts[0] {
			return fmt.Errorf("no valid certificates found in %s", base)
		}

		b.certs = append(b.certs, certs...)
		return nil
	}
}

// FromDir loads a certificate bundle from the specified directory.  This does
// not include subdirectories.
//
// If the glob patterns are specified, only matching files will be included.  If
// no glob patterns are specified, all files ending with .pem (ignoring case)
// will be included.
func FromDir(dir string, glob ...string) Option {
	return func(b *Bundle) error {
		return fromFS(os.DirFS(dir), false, glob...)(b)
	}
}

// FromFS loads a certificate bundle from the provided filesystem by recursively
// searching for PEM files and loading certificates from them.
//
// If the glob patterns are specified, only matching files will be included.  If
// no glob patterns are specified, all files ending with .pem (ignoring case)
// will be included.
func FromFS(fsys fs.FS, glob ...string) Option {
	return func(b *Bundle) error {
		return fromFS(fsys, true, glob...)(b)
	}
}

func fromFS(fsys fs.FS, recurse bool, glob ...string) Option {
	return func(b *Bundle) error {
		return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				if !recurse && path != "." {
					return fs.SkipDir
				}
				return nil
			}

			filename := filepath.Base(path)
			if !matchesPattern(filename, glob) {
				return nil
			}

			data, err := fs.ReadFile(fsys, path)
			if err != nil {
				b.logger.Warn("Failed to read file", zap.String("path", path), zap.Error(err))
				return nil
			}

			certs, err := parsePEMCertificates(data)
			if err != nil {
				b.logger.Error("Failed to parse certificates from file", zap.String("path", path), zap.Error(err))
				return nil
			}
			b.certs = append(b.certs, certs...)

			return nil
		})
	}
}

// WithData allows a blob of data to be processed as a certificate bundle.
func WithData(data []byte, errIfNoCerts ...bool) Option {
	return func(b *Bundle) error {
		certs, err := parsePEMCertificates(data)
		if err != nil {
			return err
		}

		errIfNoCerts = append(errIfNoCerts, true)

		if len(certs) == 0 && errIfNoCerts[0] {
			return fmt.Errorf("no valid certificates found in provided data")
		}

		b.certs = append(b.certs, certs...)
		return nil
	}
}

// WithCerts adds the provided certificates to the bundle.
func WithCerts(certs ...*x509.Certificate) Option {
	return func(b *Bundle) error {
		for _, cert := range certs {
			if cert != nil {
				b.certs = append(b.certs, cert)
			}
		}
		return nil
	}
}

// New creates a new empty Bundle instance.
func New(opts ...Option) (*Bundle, error) {
	b := &Bundle{
		logger: zap.NewNop(),
	}

	err := b.Add(opts...)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Add adds additional certs to the Bundle.
func (b *Bundle) Add(opts ...Option) error {
	for _, opt := range opts {
		if err := opt(b); err != nil {
			return err
		}
	}

	return nil
}

// Ordered sorts the certificates in the bundle into the proper order:
// root CAs first, then intermediate CAs in chain order, then leaf certificates.
// Ordered will not return nil as part of the list.
func (b *Bundle) Ordered() []*x509.Certificate {
	roots := make([]*x509.Certificate, 0, len(b.certs))
	intermediates := make([]*x509.Certificate, 0, len(b.certs))
	leaves := make([]*x509.Certificate, 0, len(b.certs))

	for _, cert := range b.certs {
		if cert == nil {
			continue
		}

		if isRootCA(cert) {
			roots = append(roots, cert)
			continue
		}

		if isIntermediateCA(cert) {
			intermediates = append(intermediates, cert)
			continue
		}

		leaves = append(leaves, cert)
	}

	var ordered []*x509.Certificate

	ordered = append(ordered, roots...)
	ordered = append(ordered, orderIntermediates(intermediates)...)
	ordered = append(ordered, leaves...)

	return ordered
}

// Write writes the ordered certificates to the provided writer in PEM format.
func (b *Bundle) Write(w io.Writer) error {
	orderedCerts := b.Ordered()

	for _, cert := range orderedCerts {
		err := pem.Encode(w,
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data

	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		rest = remainder
	}

	return certs, nil
}

func matchesPattern(filename string, patterns []string) bool {
	if len(patterns) == 0 {
		patterns = []string{"*.pem", "*.PEM"}
	}

	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, filename)
		if err != nil {
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// orderIntermediates attempts to order intermediate CA certificates in chain order.
// It tries to build a chain where each certificate is issued by the previous one.
func orderIntermediates(intermediates []*x509.Certificate) []*x509.Certificate {
	if len(intermediates) <= 1 {
		return intermediates
	}

	var ordered []*x509.Certificate
	remaining := make([]*x509.Certificate, len(intermediates))
	copy(remaining, intermediates)

	// Build chains starting from certificates whose issuers are not in the intermediate list
	for len(remaining) > 0 {
		chainStart := -1

		// Find a certificate whose issuer is not in the remaining list (potential chain start)
		for i, cert := range remaining {
			isChainStart := true
			for _, other := range remaining {
				if cert.Issuer.String() == other.Subject.String() {
					isChainStart = false
					break
				}
			}
			if isChainStart {
				chainStart = i
				break
			}
		}

		// If no chain start found, just take the first certificate
		if chainStart == -1 {
			chainStart = 0
		}

		// Start building a chain from this certificate
		current := remaining[chainStart]
		ordered = append(ordered, current)
		remaining = append(remaining[:chainStart], remaining[chainStart+1:]...)

		// Continue building the chain
		for len(remaining) > 0 {
			found := false
			for i, cert := range remaining {
				if cert.Issuer.String() == current.Subject.String() {
					ordered = append(ordered, cert)
					current = cert
					remaining = append(remaining[:i], remaining[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				// No continuation found, start a new chain
				break
			}
		}
	}

	return ordered
}

// isRootCA determines if a certificate is a root CA by checking if it's self-signed,
// has the CA flag set, and has certificate signing capability.
func isRootCA(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String() &&
		cert.IsCA &&
		(cert.KeyUsage&x509.KeyUsageCertSign) != 0
}

// isIntermediateCA determines if a certificate is an intermediate CA by checking
// if it's not self-signed, has the CA flag set, and has certificate signing capability.
func isIntermediateCA(cert *x509.Certificate) bool {
	return cert.Subject.String() != cert.Issuer.String() &&
		cert.IsCA &&
		(cert.KeyUsage&x509.KeyUsageCertSign) != 0
}
