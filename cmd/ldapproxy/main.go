package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	server "github.com/cloudldap/ldapproxy"
)

var (
	version  string
	revision string

	fs          = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	bindAddress = fs.String(
		"b",
		"127.0.0.1:8389",
		"Bind address",
	)
	logLevel = fs.String(
		"log-level",
		"info",
		"Log level, on of: debug, info, warn, error, alert",
	)
	pprofServer = fs.String(
		"pprof",
		"",
		"Bind address of pprof server (Don't start the server with default)",
	)
	gomaxprocs = fs.Int(
		"gomaxprocs",
		0,
		"GOMAXPROCS (Use CPU num with default)",
	)
	backendDefaultLDAP = fs.String(
		"backend-server",
		"",
		"Backend LDAP Server baseDN, address and port (e.g. myldap:389",
	)
	backendLDAPTimeout = fs.Int(
		"backend-timeout",
		10,
		"Timeout seconds",
	)
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, "\n")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var backendLDAPServers arrayFlags

func main() {
	fs.Var(&backendLDAPServers, "backend-additional-server", "Backend Additional LDAP Server. Set baseDN:address:port (e.g. dc=example,dc=com:myldap:389")

	fmt.Fprintf(os.Stdout, "ldap-proxy %s (rev: %s)\n", version, revision)
	fs.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprintf(os.Stderr, "\nUsage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatalf("error: Cannot parse the args: %v, err: %s", os.Args[1:], err)
	}

	if len(os.Args) == 1 {
		fs.Usage()
		return
	}

	backendConfig := make(server.BackendLDAPConfig)
	for _, v := range backendLDAPServers {
		s := strings.Split(v, ":")
		if len(s) == 3 {
			backendConfig[strings.ToLower(s[0])] = s[1] + ":" + s[2]
		} else {
			log.Fatalf("error: Invalid args: %v", os.Args[1:])
		}
	}

	if *backendDefaultLDAP == "" {
		fs.Usage()
		return
	}

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := server.NewServer(&server.ServerConfig{
		BindAddress:        *bindAddress,
		DefaultBackendLDAP: *backendDefaultLDAP,
		BackendLDAP:        backendConfig,
		TimoutInSeconds:    *backendLDAPTimeout,
		LogLevel:           *logLevel,
		PProfServer:        *pprofServer,
		GoMaxProcs:         *gomaxprocs,
	})

	go server.Start()

	<-ctx.Done()
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Printf("info: Shutdown ldap-proxy...")
	server.Stop()
}
