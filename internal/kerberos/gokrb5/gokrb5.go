// Package gokrb5 is the pure-Go Kerberos backend. It is the only package that imports
// github.com/jcmturner/gokrb5 (plan D13).
package gokrb5

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"

	"github.com/poliproger/soap_exporter/internal/kerberos"
)

// Name is the backend name selected with --kerberos.backend.
const Name = "gokrb5"

// Backend creates gokrb5 credentials.
type Backend struct {
	cfg    *config.Config
	logger *slog.Logger
}

var _ kerberos.Backend = (*Backend)(nil)

// New loads krb5.conf from krb5ConfPath. Directives gokrb5 does not support are logged as
// warnings, not errors.
func New(krb5ConfPath string, logger *slog.Logger) (*Backend, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	b, _, err := readFile(krb5ConfPath)
	if err != nil {
		return nil, fmt.Errorf("krb5.conf: %w", err)
	}
	cfg, err := parseKrb5Conf(b)
	if err != nil {
		var unsupported config.UnsupportedDirective
		if !errors.As(err, &unsupported) || cfg == nil {
			return nil, fmt.Errorf("krb5.conf %s: %w", krb5ConfPath, err)
		}
		logger.Warn("krb5.conf has directives gokrb5 does not support, ignoring them",
			"path", krb5ConfPath, "err", err)
	}
	return &Backend{cfg: cfg, logger: logger}, nil
}

// parseKrb5Conf parses krb5.conf contents. gokrb5 ignores the error of its line scanner, so
// a line longer than the scanner's buffer would silently end the file.
func parseKrb5Conf(b []byte) (*config.Config, error) {
	s := bufio.NewScanner(bytes.NewReader(b))
	cfg, err := config.NewFromScanner(s)
	if s.Err() != nil {
		// Reading from memory, bufio.ErrTooLong is the only possible error.
		return nil, fmt.Errorf("a line is longer than %d KiB", bufio.MaxScanTokenSize>>10)
	}
	return cfg, err
}

// Name implements kerberos.Backend.
func (b *Backend) Name() string { return Name }

// NewCredential implements kerberos.Backend.
func (b *Backend) NewCredential(principal, keytab string) (kerberos.Credential, error) {
	name, realm, err := splitPrincipal(principal)
	if err != nil {
		return nil, err
	}
	if realm == "" {
		realm = b.cfg.LibDefaults.DefaultRealm
		if realm == "" {
			return nil, fmt.Errorf("principal %q has no realm and krb5.conf sets no default_realm", principal)
		}
	}
	c := newCredential(b.cfg, b.logger, name, realm, keytab)
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// splitPrincipal splits "name@REALM" at the last "@". The realm is empty if there is no "@".
func splitPrincipal(principal string) (name, realm string, err error) {
	name = principal
	if i := strings.LastIndexByte(principal, '@'); i >= 0 {
		name, realm = principal[:i], principal[i+1:]
		if realm == "" {
			return "", "", fmt.Errorf("principal %q: empty realm", principal)
		}
	}
	if slices.Contains(strings.Split(name, "/"), "") {
		return "", "", fmt.Errorf("principal %q: empty name component", principal)
	}
	return name, realm, nil
}
