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

package store

import (
	pb "github.com/brancz/hlin/pkg/api/apipb"

	"github.com/go-kit/kit/log"
	"golang.org/x/net/context"
)

type MemStore struct {
	secretStore     map[string]*pb.PlainSecret
	sharesStore     map[string]*pb.Shares
	cipherTextStore map[string]*pb.CipherText
	logger          log.Logger
}

func NewMemStore(logger log.Logger) Store {
	return &MemStore{
		secretStore:     map[string]*pb.PlainSecret{},
		sharesStore:     map[string]*pb.Shares{},
		cipherTextStore: map[string]*pb.CipherText{},
		logger:          logger,
	}
}

func (ms *MemStore) CreateSecret(ctx context.Context, secretId string, s *pb.CreateSecretRequest) (*pb.PlainSecret, error) {
	ps := &pb.PlainSecret{SecretId: secretId}
	ms.secretStore[secretId] = ps
	ms.sharesStore[secretId] = s.Shares
	ms.cipherTextStore[secretId] = s.CipherText
	ms.logger.Log("msg", "secret created", "id", secretId)
	return ps, nil
}

func (ms *MemStore) GetSecret(ctx context.Context, secretId string) (*pb.PlainSecret, error) {
	s, ok := ms.secretStore[secretId]
	if !ok {
		ms.logger.Log("err", SecretNotFound, "id", secretId)
		return nil, SecretNotFound
	}
	ms.logger.Log("msg", "secret retrieved", "id", secretId)
	return s, nil
}

func (ms *MemStore) GetShares(ctx context.Context, secretId string) (*pb.Shares, error) {
	s, ok := ms.sharesStore[secretId]
	if !ok {
		ms.logger.Log("err", SharesNotFound, "id", secretId)
		return nil, SharesNotFound
	}
	ms.logger.Log("msg", "shares retrieved", "id", secretId)
	return s, nil
}

func (ms *MemStore) GetCipherText(ctx context.Context, secretId string) (*pb.CipherText, error) {
	s, ok := ms.cipherTextStore[secretId]
	if !ok {
		ms.logger.Log("err", CipherTextNotFound, "id", secretId)
		return nil, CipherTextNotFound
	}
	ms.logger.Log("msg", "cipher text retrieved", "id", secretId)
	return s, nil
}
