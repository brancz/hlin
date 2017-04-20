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

package api

import (
	pb "github.com/brancz/hlin/pkg/api/apipb"

	"github.com/go-kit/kit/log"
	context "golang.org/x/net/context"
)

type SecretStore interface {
	Get(id string) (*pb.Secret, error)
	Create(s *pb.Secret) (*pb.Secret, error)
}

type API struct {
	store  SecretStore
	logger log.Logger
}

func NewAPIServer(logger log.Logger, s SecretStore) pb.APIServer {
	return &API{
		store:  s,
		logger: logger,
	}
}

func (a *API) GetSecret(ctx context.Context, r *pb.GetSecretRequest) (*pb.Secret, error) {
	return a.store.Get(r.SecretId)
}

func (a *API) CreateSecret(ctx context.Context, s *pb.Secret) (*pb.Secret, error) {
	return a.store.Create(s)
}
