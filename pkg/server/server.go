// Copyright 2017 The hlin Authors
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

package server

import (
	"time"

	"github.com/go-kit/kit/log"
	"golang.org/x/net/context"
)

type Server struct {
	logger log.Logger
}

func NewServer(logger log.Logger) *Server {
	return &Server{
		logger: logger,
	}
}

func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(time.Second * 10)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Log("msg", "returning")
			return
		case <-t.C:
			s.logger.Log("msg", "tick")
		}
	}
}
