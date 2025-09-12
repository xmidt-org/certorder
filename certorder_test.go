// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package certorder

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		opts        []Option
		wantErr     bool
		certCount   int
	}{
		{
			name:      "empty bundle",
			opts:      nil,
			wantErr:   false,
			certCount: 0,
		},
		{
			name: "with single cert",
			opts: []Option{
				WithCerts(createTestCert(t, "leaf", false, false)),
			},
			wantErr:   false,
			certCount: 1,
		},
		{
			name: "with multiple certs",
			opts: []Option{
				WithCerts(
					createTestCert(t, "root", true, true),
					createTestCert(t, "intermediate", true, false),
					createTestCert(t, "leaf", false, false),
				),
			},
			wantErr:   false,
			certCount: 3,
		},
		{
			name: "with nil cert",
			opts: []Option{
				WithCerts(nil, createTestCert(t, "leaf", false, false)),
			},
			wantErr:   false,
			certCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := New(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(bundle.certs) != tt.certCount {
				t.Errorf("New() cert count = %v, want %v", len(bundle.certs), tt.certCount)
			}
		})
	}
}

func TestBundle_Add(t *testing.T) {
	tests := []struct {
		name        string
		initialOpts []Option
		addOpts     []Option
		wantErr     bool
		finalCount  int
	}{
		{
			name:        "add to empty bundle",
			initialOpts: nil,
			addOpts: []Option{
				WithCerts(createTestCert(t, "test", false, false)),
			},
			wantErr:    false,
			finalCount: 1,
		},
		{
			name: "add to existing bundle",
			initialOpts: []Option{
				WithCerts(createTestCert(t, "existing", false, false)),
			},
			addOpts: []Option{
				WithCerts(createTestCert(t, "new", false, false)),
			},
			wantErr:    false,
			finalCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := New(tt.initialOpts...)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			err = bundle.Add(tt.addOpts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Bundle.Add() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(bundle.certs) != tt.finalCount {
				t.Errorf("Bundle.Add() final count = %v, want %v", len(bundle.certs), tt.finalCount)
			}
		})
	}
}

func TestBundle_Ordered(t *testing.T) {
	// Create simple test cases with individual certificates
	rootCert := createTestCert(t, "root", true, true)
	intermediateCert := createTestCert(t, "intermediate", true, false)
	leafCert := createTestCert(t, "leaf", false, false)

	// Create a proper certificate chain for more complex testing
	rootCA, intermediate1, intermediate2, leaf := createCertificateChain(t)

	tests := []struct {
		name     string
		certs    []*x509.Certificate
		expected []string
	}{
		{
			name:     "empty bundle",
			certs:    nil,
			expected: nil,
		},
		{
			name:     "single cert",
			certs:    []*x509.Certificate{leafCert},
			expected: []string{"leaf"},
		},
		{
			name:     "simple chain proper order",
			certs:    []*x509.Certificate{rootCert, intermediateCert, leafCert},
			expected: []string{"root", "intermediate", "leaf"},
		},
		{
			name:     "simple chain reverse order",
			certs:    []*x509.Certificate{leafCert, intermediateCert, rootCert},
			expected: []string{"root", "intermediate", "leaf"},
		},
		{
			name:     "proper certificate chain in order",
			certs:    []*x509.Certificate{rootCA, intermediate1, intermediate2, leaf},
			expected: []string{"Test Root CA", "Test Intermediate CA 1", "Test Intermediate CA 2", "Test Leaf"},
		},
		{
			name:     "proper certificate chain reverse order",
			certs:    []*x509.Certificate{leaf, intermediate2, intermediate1, rootCA},
			expected: []string{"Test Root CA", "Test Intermediate CA 1", "Test Intermediate CA 2", "Test Leaf"},
		},
		{
			name:     "proper certificate chain mixed order",
			certs:    []*x509.Certificate{intermediate2, leaf, rootCA, intermediate1},
			expected: []string{"Test Root CA", "Test Intermediate CA 1", "Test Intermediate CA 2", "Test Leaf"},
		},
		{
			name:     "only intermediates from proper chain",
			certs:    []*x509.Certificate{intermediate2, intermediate1},
			expected: []string{"Test Intermediate CA 1", "Test Intermediate CA 2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := &Bundle{certs: tt.certs}
			ordered := bundle.Ordered()

			if len(ordered) != len(tt.expected) {
				t.Errorf("Ordered() length = %v, want %v", len(ordered), len(tt.expected))
				return
			}

			for i, expectedName := range tt.expected {
				if ordered[i].Subject.CommonName != expectedName {
					t.Errorf("Ordered()[%d] = %v, want %v", i, ordered[i].Subject.CommonName, expectedName)
				}
			}
		})
	}
}

func TestOrderIntermediates(t *testing.T) {
	// Create a proper certificate chain for testing
	_, intermediate1, intermediate2, _ := createCertificateChain(t)
	
	// Create some additional intermediates with different relationships
	intermediate3 := createTestCert(t, "intermediate3", true, false)
	intermediate4 := createTestCert(t, "intermediate4", true, false)

	tests := []struct {
		name         string
		intermediates []*x509.Certificate
		expected     []string
	}{
		{
			name:         "empty list",
			intermediates: nil,
			expected:     nil,
		},
		{
			name:         "single intermediate",
			intermediates: []*x509.Certificate{intermediate1},
			expected:     []string{"Test Intermediate CA 1"},
		},
		{
			name:         "two intermediates proper order",
			intermediates: []*x509.Certificate{intermediate1, intermediate2},
			expected:     []string{"Test Intermediate CA 1", "Test Intermediate CA 2"},
		},
		{
			name:         "two intermediates reverse order",
			intermediates: []*x509.Certificate{intermediate2, intermediate1},
			expected:     []string{"Test Intermediate CA 1", "Test Intermediate CA 2"},
		},
		{
			name:         "intermediates with no clear chain",
			intermediates: []*x509.Certificate{intermediate3, intermediate4},
			expected:     []string{"intermediate3", "intermediate4"}, // Should preserve order when no clear chain
		},
		{
			name:         "mixed chainable and non-chainable",
			intermediates: []*x509.Certificate{intermediate3, intermediate2, intermediate1},
			expected:     []string{"intermediate3", "Test Intermediate CA 1", "Test Intermediate CA 2"}, // Non-chainable first, then chain
		},
		{
			name:         "three intermediates in mixed order",
			intermediates: []*x509.Certificate{intermediate2, intermediate3, intermediate1},
			expected:     []string{"intermediate3", "Test Intermediate CA 1", "Test Intermediate CA 2"}, // Non-chainable first, then chain
		},
		{
			name:         "circular reference scenario",
			intermediates: []*x509.Certificate{createCircularCert(t, "cert1", "cert2"), createCircularCert(t, "cert2", "cert1")},
			expected:     []string{"cert1", "cert2"}, // Should handle circular refs by taking first available
		},
		{
			name:         "broken chain with orphaned cert",
			intermediates: []*x509.Certificate{intermediate1, createOrphanedCert(t, "orphan", "nonexistent-issuer")},
			expected:     []string{"Test Intermediate CA 1", "orphan"}, // Algorithm finds intermediate1 first
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ordered := orderIntermediates(tt.intermediates)
			
			if len(ordered) != len(tt.expected) {
				t.Errorf("orderIntermediates() length = %v, want %v", len(ordered), len(tt.expected))
				return
			}

			for i, expectedName := range tt.expected {
				if ordered[i].Subject.CommonName != expectedName {
					t.Errorf("orderIntermediates()[%d] = %v, want %v", i, ordered[i].Subject.CommonName, expectedName)
				}
			}
		})
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		patterns []string
		want     bool
	}{
		{
			name:     "default pem lowercase",
			filename: "test.pem",
			patterns: nil,
			want:     true,
		},
		{
			name:     "default pem uppercase",
			filename: "test.PEM",
			patterns: nil,
			want:     true,
		},
		{
			name:     "default pem mixed case",
			filename: "test.Pem",
			patterns: nil,
			want:     true,
		},
		{
			name:     "default non-pem",
			filename: "test.txt",
			patterns: nil,
			want:     false,
		},
		{
			name:     "specific pattern match",
			filename: "test.cert",
			patterns: []string{"*.cert"},
			want:     true,
		},
		{
			name:     "specific pattern no match",
			filename: "test.pem",
			patterns: []string{"*.cert"},
			want:     false,
		},
		{
			name:     "multiple patterns first match",
			filename: "test.pem",
			patterns: []string{"*.pem", "*.cert"},
			want:     true,
		},
		{
			name:     "multiple patterns second match",
			filename: "test.cert",
			patterns: []string{"*.pem", "*.cert"},
			want:     true,
		},
		{
			name:     "multiple patterns no match",
			filename: "test.txt",
			patterns: []string{"*.pem", "*.cert"},
			want:     false,
		},
		{
			name:     "invalid pattern ignored",
			filename: "test.pem",
			patterns: []string{"[invalid", "*.pem"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesPattern(tt.filename, tt.patterns); got != tt.want {
				t.Errorf("matchesPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	testCert := createTestCert(t, "test", false, false)

	validFile := filepath.Join(tmpDir, "valid.pem")
	createPEMFile(t, validFile, testCert)

	invalidFile := filepath.Join(tmpDir, "invalid.pem")
	if err := os.WriteFile(invalidFile, []byte("invalid pem content"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		filename  string
		wantErr   bool
		certCount int
	}{
		{
			name:      "valid file",
			filename:  validFile,
			wantErr:   false,
			certCount: 1,
		},
		{
			name:      "non-existent file",
			filename:  filepath.Join(tmpDir, "nonexistent.pem"),
			wantErr:   true,
			certCount: 0,
		},
		{
			name:      "invalid pem file",
			filename:  invalidFile,
			wantErr:   false,
			certCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := &Bundle{}
			opt := FromFile(tt.filename)
			err := opt(bundle)

			if (err != nil) != tt.wantErr {
				t.Errorf("FromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(bundle.certs) != tt.certCount {
				t.Errorf("FromFile() cert count = %v, want %v", len(bundle.certs), tt.certCount)
			}
		})
	}
}

func TestFromDir(t *testing.T) {
	tmpDir := t.TempDir()
	testCert1 := createTestCert(t, "test1", false, false)
	testCert2 := createTestCert(t, "test2", false, false)

	createPEMFile(t, filepath.Join(tmpDir, "cert1.pem"), testCert1)
	createPEMFile(t, filepath.Join(tmpDir, "cert2.PEM"), testCert2)
	createPEMFile(t, filepath.Join(tmpDir, "cert3.txt"), testCert1)

	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	createPEMFile(t, filepath.Join(subDir, "cert4.pem"), testCert2)

	tests := []struct {
		name      string
		dir       string
		glob      []string
		wantErr   bool
		certCount int
	}{
		{
			name:      "default pattern",
			dir:       tmpDir,
			glob:      nil,
			wantErr:   false,
			certCount: 2, // cert1.pem and cert2.PEM
		},
		{
			name:      "specific glob pattern",
			dir:       tmpDir,
			glob:      []string{"*.txt"},
			wantErr:   false,
			certCount: 1, // cert3.txt
		},
		{
			name:      "multiple glob patterns",
			dir:       tmpDir,
			glob:      []string{"*.pem", "*.txt"},
			wantErr:   false,
			certCount: 2, // cert1.pem and cert3.txt
		},
		{
			name:      "non-existent directory",
			dir:       filepath.Join(tmpDir, "nonexistent"),
			glob:      nil,
			wantErr:   true,
			certCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := &Bundle{}
			opt := FromDir(tt.dir, tt.glob...)
			err := opt(bundle)

			if (err != nil) != tt.wantErr {
				t.Errorf("FromDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(bundle.certs) != tt.certCount {
				t.Errorf("FromDir() cert count = %v, want %v", len(bundle.certs), tt.certCount)
			}
		})
	}
}

func TestFromFS(t *testing.T) {
	testCert1 := createTestCert(t, "test1", false, false)
	testCert2 := createTestCert(t, "test2", false, false)

	cert1PEM := certToPEM(testCert1)
	cert2PEM := certToPEM(testCert2)

	fsys := fstest.MapFS{
		"cert1.pem":        &fstest.MapFile{Data: cert1PEM},
		"cert2.PEM":        &fstest.MapFile{Data: cert2PEM},
		"cert3.txt":        &fstest.MapFile{Data: cert1PEM},
		"subdir/cert4.pem": &fstest.MapFile{Data: cert2PEM},
		"invalid.pem":      &fstest.MapFile{Data: []byte("invalid")},
	}

	tests := []struct {
		name      string
		fsys      fs.FS
		glob      []string
		certCount int
	}{
		{
			name:      "default pattern",
			fsys:      fsys,
			glob:      nil,
			certCount: 3, // cert1.pem, cert2.PEM, subdir/cert4.pem
		},
		{
			name:      "specific glob pattern",
			fsys:      fsys,
			glob:      []string{"*.txt"},
			certCount: 1, // cert3.txt
		},
		{
			name:      "multiple glob patterns",
			fsys:      fsys,
			glob:      []string{"*.pem", "*.txt"},
			certCount: 3, // cert1.pem, cert3.txt, and subdir/cert4.pem
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := &Bundle{}
			opt := FromFS(tt.fsys, tt.glob...)
			err := opt(bundle)

			if err != nil {
				t.Errorf("FromFS() error = %v", err)
				return
			}
			if len(bundle.certs) != tt.certCount {
				t.Errorf("FromFS() cert count = %v, want %v", len(bundle.certs), tt.certCount)
			}
		})
	}
}

func TestIsRootCA(t *testing.T) {
	tests := []struct {
		name   string
		cert   *x509.Certificate
		isRoot bool
	}{
		{
			name:   "root CA",
			cert:   createTestCert(t, "root", true, true),
			isRoot: true,
		},
		{
			name:   "intermediate CA",
			cert:   createTestCert(t, "intermediate", true, false),
			isRoot: false,
		},
		{
			name:   "leaf certificate",
			cert:   createTestCert(t, "leaf", false, false),
			isRoot: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRootCA(tt.cert); got != tt.isRoot {
				t.Errorf("isRootCA() = %v, want %v", got, tt.isRoot)
			}
		})
	}
}

func TestIsIntermediateCA(t *testing.T) {
	tests := []struct {
		name           string
		cert           *x509.Certificate
		isIntermediate bool
	}{
		{
			name:           "root CA",
			cert:           createTestCert(t, "root", true, true),
			isIntermediate: false,
		},
		{
			name:           "intermediate CA",
			cert:           createTestCert(t, "intermediate", true, false),
			isIntermediate: true,
		},
		{
			name:           "leaf certificate",
			cert:           createTestCert(t, "leaf", false, false),
			isIntermediate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIntermediateCA(tt.cert); got != tt.isIntermediate {
				t.Errorf("isIntermediateCA() = %v, want %v", got, tt.isIntermediate)
			}
		})
	}
}

func TestBundle_Write(t *testing.T) {
	rootCert := createTestCert(t, "root", true, true)
	intermediateCert := createTestCert(t, "intermediate", true, false)
	leafCert := createTestCert(t, "leaf", false, false)

	bundle := &Bundle{
		certs: []*x509.Certificate{leafCert, intermediateCert, rootCert},
	}

	var buf strings.Builder
	err := bundle.Write(&buf)
	if err != nil {
		t.Fatalf("Bundle.Write() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "-----BEGIN CERTIFICATE-----") {
		t.Error("Bundle.Write() output missing PEM header")
	}
	if !strings.Contains(output, "-----END CERTIFICATE-----") {
		t.Error("Bundle.Write() output missing PEM footer")
	}

	blocks := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	if blocks != 3 {
		t.Errorf("Bundle.Write() output has %d certificate blocks, want 3", blocks)
	}
}

// Helper functions for testing

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	issuerKeyOnce sync.Once
	issuerKey   *rsa.PrivateKey
)

func getTestKey() *rsa.PrivateKey {
	testKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 1024) // Smaller key for faster tests
		if err != nil {
			panic(err)
		}
		testKey = key
	})
	return testKey
}

func getIssuerKey() *rsa.PrivateKey {
	issuerKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 1024) // Smaller key for faster tests
		if err != nil {
			panic(err)
		}
		issuerKey = key
	})
	return issuerKey
}

func createTestCert(t *testing.T, commonName string, isCA, isSelfSigned bool) *x509.Certificate {
	t.Helper()

	privateKey := getTestKey()

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         isCA,
		BasicConstraintsValid: true,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var parent *x509.Certificate
	var parentKey any

	if isSelfSigned {
		template.Issuer = template.Subject
		parent = &template
		parentKey = privateKey
	} else {
		// Create a different issuer with different subject info
		issuerPrivateKey := getIssuerKey()
		
		issuerTemplate := x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName:   "issuer-" + commonName,
				Organization: []string{"Different Org"},
			},
			Issuer: pkix.Name{
				CommonName:   "issuer-" + commonName,
				Organization: []string{"Different Org"},
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			IsCA:         true,
			BasicConstraintsValid: true,
		}

		issuerCertDER, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &issuerPrivateKey.PublicKey, issuerPrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		parent, err = x509.ParseCertificate(issuerCertDER)
		if err != nil {
			t.Fatal(err)
		}

		template.Issuer = parent.Subject
		parentKey = issuerPrivateKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func createCertificateChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	// Create root CA
	rootKey := getTestKey()
	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootTemplate.Issuer = rootTemplate.Subject

	rootCertDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatal(err)
	}

	// Create first intermediate CA (signed by root)
	intermediate1Key := getIssuerKey()
	intermediate1Template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA 1",
			Organization: []string{"Test Org"},
		},
		Issuer:                rootCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	intermediate1CertDER, err := x509.CreateCertificate(rand.Reader, &intermediate1Template, rootCert, &intermediate1Key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate1Cert, err := x509.ParseCertificate(intermediate1CertDER)
	if err != nil {
		t.Fatal(err)
	}

	// Create second intermediate CA (signed by first intermediate)
	intermediate2Key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	intermediate2Template := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA 2",
			Organization: []string{"Test Org"},
		},
		Issuer:                intermediate1Cert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	intermediate2CertDER, err := x509.CreateCertificate(rand.Reader, &intermediate2Template, intermediate1Cert, &intermediate2Key.PublicKey, intermediate1Key)
	if err != nil {
		t.Fatal(err)
	}
	intermediate2Cert, err := x509.ParseCertificate(intermediate2CertDER)
	if err != nil {
		t.Fatal(err)
	}

	// Create leaf certificate (signed by second intermediate)
	leafKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			CommonName: "Test Leaf",
		},
		Issuer:                intermediate2Cert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, intermediate2Cert, &leafKey.PublicKey, intermediate2Key)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatal(err)
	}

	return rootCert, intermediate1Cert, intermediate2Cert, leafCert
}

func createCircularCert(t *testing.T, commonName, issuerName string) *x509.Certificate {
	t.Helper()

	privateKey := getTestKey()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		Issuer: pkix.Name{
			CommonName: issuerName, // Different from subject to create circular reference
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func createOrphanedCert(t *testing.T, commonName, issuerName string) *x509.Certificate {
	t.Helper()

	privateKey := getTestKey()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		Issuer: pkix.Name{
			CommonName: issuerName, // Non-existent issuer
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func createPEMFile(t *testing.T, filename string, cert *x509.Certificate) {
	t.Helper()

	pemData := certToPEM(cert)
	if err := os.WriteFile(filename, pemData, 0644); err != nil {
		t.Fatal(err)
	}
}

func certToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}