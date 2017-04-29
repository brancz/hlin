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
	"github.com/brancz/hlin/pkg/store"

	"github.com/go-kit/kit/log"
	context "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	//"google.golang.org/grpc/metadata"
)

type API struct {
	store  store.Store
	logger log.Logger
}

func NewAPIServer(logger log.Logger, s store.Store) pb.APIServer {
	return &API{
		store:  s,
		logger: logger,
	}
}

func (a *API) CreateSecret(ctx context.Context, s *pb.CreateSecretRequest) (*pb.PlainSecret, error) {
	return a.store.CreateSecret(s)
}

func (a *API) GetSecret(ctx context.Context, r *pb.GetSecretRequest) (*pb.PlainSecret, error) {
	s, err := a.store.GetSecret(r.SecretId)
	if err == store.SecretNotFound {
		return nil, grpc.Errorf(codes.NotFound, "secret not found")
	}
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (a *API) GetShares(ctx context.Context, r *pb.GetSharesRequest) (*pb.Shares, error) {
	s, err := a.store.GetShares(r.SecretId)
	if err == store.SharesNotFound {
		return nil, grpc.Errorf(codes.NotFound, "shares not found")
	}
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (a *API) GetCipherText(ctx context.Context, r *pb.GetCipherTextRequest) (*pb.CipherText, error) {
	s, err := a.store.GetCipherText(r.SecretId)
	if err == store.CipherTextNotFound {
		return nil, grpc.Errorf(codes.NotFound, "cipher text not found")
	}
	if err != nil {
		return nil, err
	}

	return s, nil
}
