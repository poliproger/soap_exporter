//go:build integration

package integration

import (
	"log/slog"

	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/kerberos/gokrb5"
)

// backend is a Kerberos backend under test. The suite runs once for every backend that ships
// (plan §10, A.9); a backend behind a build tag adds itself to backends from an init function
// in a file with the same tag.
type backend struct {
	name string
	new  func(krb5Conf string, logger *slog.Logger) (kerberos.Backend, error)
	// kvnoWorkaroundLog is part of the info message the backend logs when it applies the kvno
	// workaround to a keytab whose entries all have kvno 0 (plan finding 8); empty if the
	// backend needs no workaround.
	kvnoWorkaroundLog string
	// renewsTGT: the backend renews its TGT before it expires, while the TGT is renewable. A
	// backend that only logs in again from the keytab (as MIT GSSAPI does) leaves it false.
	renewsTGT bool
}

var backends = []backend{{
	name: gokrb5.Name,
	new: func(krb5Conf string, logger *slog.Logger) (kerberos.Backend, error) {
		b, err := gokrb5.New(krb5Conf, logger)
		if err != nil {
			return nil, err // not a nil *gokrb5.Backend in a non-nil interface
		}
		return b, nil
	},
	kvnoWorkaroundLog: "(kvno workaround)",
	renewsTGT:         true, // the gokrb5 client renews at 5/6 of the TGT's lifetime
}}
