package main

import (
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/common/promslog"
	promslogflag "github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	toolkitweb "github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/kerberos/gokrb5"
)

const (
	defaultListenAddress = ":10057" // plan D14
	defaultKrb5Config    = "/etc/krb5.conf"
	// exitUsage is the exit code of invalid command-line arguments.
	exitUsage = 2
)

// kerberosBackends are the Kerberos backends compiled into this build by name
// (--kerberos.backend); a build-tagged file may add one (plan D13).
var kerberosBackends = map[string]func(krb5Config string, logger *slog.Logger) (kerberos.Backend, error){
	gokrb5.Name: func(krb5Config string, logger *slog.Logger) (kerberos.Backend, error) {
		b, err := gokrb5.New(krb5Config, logger)
		if err != nil {
			return nil, err // not a nil *gokrb5.Backend in a non-nil interface
		}
		return b, nil
	},
}

// options are the parsed command-line flags.
type options struct {
	configFile      string
	configCheck     bool
	web             *toolkitweb.FlagConfig
	enableLifecycle bool
	log             promslog.Config
	krb5Config      string
	kerberosBackend string
	historyLimit    int
	captureBodies   bool
}

// newKerberosBackend returns the app's Options.NewBackend for the selected backend.
func (o *options) newKerberosBackend(logger *slog.Logger) func() (kerberos.Backend, error) {
	return func() (kerberos.Backend, error) {
		return kerberosBackends[o.kerberosBackend](o.krb5Config, logger)
	}
}

// terminated is the panic value of kingpin's terminate function, so that --help and
// --version end parsing without exiting the process.
type terminated int

// parseFlags parses args. If ok is false, the caller exits with code: after --help or
// --version, or on invalid arguments, which parseFlags has reported to stderr.
func parseFlags(args []string, stdout, stderr io.Writer) (o *options, code int, ok bool) {
	o = &options{}
	a := kingpin.New("soap_exporter", "A Prometheus exporter that probes SOAP services on its own "+
		"schedule and exposes the results of the last probes.")
	a.Flag("config.file", "Path to the configuration file.").
		Default("/etc/soap_exporter/config.yml").StringVar(&o.configFile)
	a.Flag("config.check", "Validate the configuration file and, if set, the web configuration file, "+
		"initialize the Kerberos backend if a target uses Kerberos, and exit.").BoolVar(&o.configCheck)
	o.web = kingpinflag.AddFlags(a, defaultListenAddress)
	a.Flag("web.enable-lifecycle", "Enable configuration reload (POST /-/reload), log level changes "+
		"(PUT /-/log-level) and on-demand probes (POST /debug/probe) over HTTP.").BoolVar(&o.enableLifecycle)
	promslogflag.AddFlags(a, &o.log)
	backends := slices.Sorted(maps.Keys(kerberosBackends))
	a.Flag("kerberos.config-file", "Path to the Kerberos configuration file (krb5.conf). Read only if a "+
		"target uses Kerberos, and only once: changes take effect after a restart, not on a reload.").
		Envar("KRB5_CONFIG").Default(defaultKrb5Config).StringVar(&o.krb5Config)
	a.Flag("kerberos.backend", "Kerberos implementation. One of: ["+strings.Join(backends, ", ")+"]").
		Default(gokrb5.Name).EnumVar(&o.kerberosBackend, backends...)
	a.Flag("history.limit", "Number of recent probe results kept per target for /debug/probes.").
		Default("20").IntVar(&o.historyLimit)
	a.Flag("debug.capture-bodies", "Keep response body snippets in the probe history. On-demand probes "+
		"always include them.").BoolVar(&o.captureBodies)
	a.Version(version.Print("soap_exporter"))
	a.HelpFlag.Short('h')
	a.UsageWriter(stdout)
	a.ErrorWriter(stderr)
	a.Terminate(func(code int) { panic(terminated(code)) })

	defer func() {
		if r := recover(); r != nil {
			c, isTerminated := r.(terminated)
			if !isTerminated {
				panic(r)
			}
			o, code, ok = nil, int(c), false
		}
	}()
	if _, err := a.Parse(args); err != nil {
		a.Errorf("%s, try --help", err)
		return nil, exitUsage, false
	}
	if o.historyLimit < 0 {
		a.Errorf("--history.limit must not be negative, got %d", o.historyLimit)
		return nil, exitUsage, false
	}
	return o, 0, true
}
