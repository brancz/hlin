// Copyright 2016 The hlin Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	etcdclient "github.com/coreos/etcd/clientv3"
	"github.com/go-kit/kit/log"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/brancz/hlin/pkg/api"
	pb "github.com/brancz/hlin/pkg/api/apipb"
	"github.com/brancz/hlin/pkg/config"
	"github.com/brancz/hlin/pkg/crypto"
	"github.com/brancz/hlin/pkg/store"
)

var (
	Version string
)

type options struct {
	certFile      string
	keyFile       string
	caFile        string
	etcd          []string
	port          int
	telemetryPort int
	configFile    string
}

func Main() int {
	logger := log.NewContext(log.NewLogfmtLogger(os.Stdout)).
		With("ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	opts := options{}
	flags := pflag.NewFlagSet("hlin", pflag.ExitOnError)
	flags.StringVar(&opts.configFile, "config-file", "", "The config file to load and use.")
	flags.StringVar(&opts.certFile, "cert-file", "", "The plaintext secret to encrypt and store.")
	flags.StringVar(&opts.keyFile, "key-file", "", "The plaintext secret to encrypt and store.")
	flags.StringVar(&opts.caFile, "ca-file", "", "The plaintext secret to encrypt and store.")
	flags.StringSliceVarP(&opts.etcd, "etcd", "e", []string{}, "The etcd instances to use for storage (repeatable).")
	flags.IntVarP(&opts.port, "port", "p", 10000, "Port to bind the server to.")
	flags.IntVar(&opts.telemetryPort, "telemetry-port", 10010, "Port to bind the HTTP server serving metrics to.")
	flags.Parse(os.Args[1:])

	cfg, err := config.FromFile(opts.configFile)
	if err != nil {
		logger.Log("msg", "failed to load config file", "err", err)
		return 1
	}

	c, err := etcdclient.New(etcdclient.Config{
		Endpoints:   opts.etcd,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		logger.Log("msg", "failed to instantiate etcd client", "err", err)
		return 1
	}
	defer c.Close()

	r := prometheus.NewRegistry()
	r.MustRegister(prometheus.NewGoCollector())
	r.MustRegister(prometheus.NewProcessCollector(os.Getpid(), ""))

	storage := store.NewEtcdStore(c, logger.With("component", "store"))

	encryptor, err := crypto.LoadTLSEncryptor(opts.certFile, opts.keyFile)
	if err != nil {
		logger.Log("msg", "loading tls encryptor failed", "err", err)
		return 1
	}

	participants := make(map[string]crypto.Participant, len(cfg.Members))
	for _, member := range cfg.Members {
		p, err := crypto.LoadX509Participant(member.CertFile)
		if err != nil {
			logger.Log("msg", "loading participant failed", "err", err)
			return 1
		}
		participants[p.Identifier()] = p
	}
	keyStore := crypto.NewMemoryKeyStore(participants, encryptor)

	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(opts.caFile)
	if err != nil {
		logger.Log("msg", "failed to read client ca cert", "err", err)
		return 1
	}

	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		logger.Log("msg", "failed to append client certs")
		return 1
	}

	creds := credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{encryptor.TlsCert},
		ClientCAs:    certPool,
	})

	grpcMetrics := grpc_prometheus.NewServerMetrics()
	gs := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpcMetrics.StreamServerInterceptor()),
		grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
	)

	as := api.NewAPIServer(
		logger.With("component", "api"),
		storage,
		keyStore,
	)

	pb.RegisterAPIServer(gs, as)
	grpcMetrics.Register(r)
	grpcMetrics.InitializeMetrics(gs)

	grpcAddr := fmt.Sprintf(":%d", opts.port)
	gl, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		logger.Log("err", err)
		return 1
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	srv := &http.Server{Handler: mux}

	httpAddr := fmt.Sprintf(":%d", opts.telemetryPort)
	hl, err := net.Listen("tcp", httpAddr)
	if err != nil {
		logger.Log("err", err)
		return 1
	}

	go gs.Serve(gl)
	logger.Log("msg", fmt.Sprintf("gRPC server listening on %s", grpcAddr))

	go srv.Serve(hl)
	logger.Log("msg", fmt.Sprintf("HTTP server listening on %s", httpAddr))

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		logger.Log("msg", "Received SIGTERM, exiting gracefully...")
	}

	return 0
}

func main() {
	os.Exit(Main())
}
