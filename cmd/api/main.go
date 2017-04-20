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
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/brancz/hlin/pkg/api"
	pb "github.com/brancz/hlin/pkg/api/apipb"

	"github.com/go-kit/kit/log"
	"google.golang.org/grpc"
)

var (
	Version string
)

func Main() int {
	gs := grpc.NewServer()

	logger := log.NewContext(log.NewLogfmtLogger(os.Stdout)).
		With("ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	as := api.NewAPIServer(
		logger.With("component", "api"),
		api.NewMemStore(logger.With("component", "store")),
	)

	pb.RegisterAPIServer(gs, as)

	l, err := net.Listen("tcp", ":10000")
	if err != nil {
		logger.Log("err", err)
		return 1
	}

	go gs.Serve(l)
	logger.Log("msg", "http server listening on :10000")

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
