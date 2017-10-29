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
	"github.com/brancz/hlin/pkg/crypto"
	"github.com/brancz/hlin/pkg/store"

	"github.com/go-kit/kit/log"
	uuid "github.com/satori/go.uuid"
	context "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type API struct {
	secretStore store.SecretStore
	keyStore    crypto.KeyStore
	logger      log.Logger
}

func NewAPIServer(logger log.Logger, sStore store.SecretStore, kStore crypto.KeyStore) pb.APIServer {
	return &API{
		secretStore: sStore,
		logger:      logger,
		keyStore:    kStore,
	}
}

func (a *API) CreateSecret(ctx context.Context, s *pb.CreateSecretRequest) (*pb.SimpleSecret, error) {
	return a.secretStore.CreateSecret(ctx, uuid.NewV4().String(), s)
}

func (a *API) GetSecret(ctx context.Context, r *pb.GetSecretRequest) (*pb.SimpleSecret, error) {
	s, err := a.secretStore.GetSecret(ctx, r.SecretId)
	if err == store.SecretNotFound {
		return nil, grpc.Errorf(codes.NotFound, "secret not found")
	}
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (a *API) GetPublicShares(ctx context.Context, r *pb.GetPublicSharesRequest) (*pb.PublicShares, error) {
	s, err := a.secretStore.GetPublicShares(ctx, r.SecretId)
	if err == store.SharesNotFound {
		return nil, grpc.Errorf(codes.NotFound, "public shares not found")
	}
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (a *API) GetPrivateShares(ctx context.Context, r *pb.GetPrivateSharesRequest) (*pb.PrivateShares, error) {
	p, err := a.keyStore.Participant(r.Requester)
	if err == crypto.ParticipantNotFound {
		return nil, grpc.Errorf(codes.NotFound, "key for requester not found")
	}
	if err != nil {
		return nil, err
	}

	s, err := a.secretStore.GetPrivateShares(ctx, r.SecretId, a.keyStore.Encryptor().Identifier())
	if err == store.SharesNotFound {
		return nil, grpc.Errorf(codes.NotFound, "private shares not found")
	}
	if err != nil {
		return nil, err
	}

	for i := range s.Items {
		plaintext, err := a.keyStore.Encryptor().Decrypt(s.Items[i].Content.Bytes)
		if err != nil {
			return nil, err
		}
		encryptedPrivateShare, err := crypto.EncryptPrivateShare(a.keyStore.Encryptor(), p, plaintext)
		if err != nil {
			return nil, err
		}
		s.Items[i] = encryptedPrivateShare
	}

	return s, nil
}

func (a *API) GetCipherText(ctx context.Context, r *pb.GetCipherTextRequest) (*pb.CipherText, error) {
	s, err := a.secretStore.GetCipherText(ctx, r.SecretId)
	if err == store.CipherTextNotFound {
		return nil, grpc.Errorf(codes.NotFound, "cipher text not found")
	}
	if err != nil {
		return nil, err
	}

	return s, nil
}
