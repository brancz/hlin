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
	"errors"

	pb "github.com/brancz/hlin/pkg/api/apipb"

	"github.com/go-kit/kit/log"
	"github.com/satori/go.uuid"
)

var SecretNotFound = errors.New("secret not found")

type MemStore struct {
	store  map[string]*pb.Secret
	logger log.Logger
}

func NewMemStore(logger log.Logger) SecretStore {
	return &MemStore{
		store:  map[string]*pb.Secret{},
		logger: logger,
	}
}

func (ms *MemStore) Create(s *pb.Secret) (*pb.Secret, error) {
	s.Id = uuid.NewV4().String()
	ms.store[s.Id] = s
	ms.logger.Log("msg", "secret created", "id", s.Id)
	return s, nil
}

func (ms *MemStore) Get(id string) (*pb.Secret, error) {
	s, ok := ms.store[id]
	if !ok {
		ms.logger.Log("msg", "secret not found", "id", id)
		return nil, SecretNotFound
	}
	ms.logger.Log("msg", "secret retrieved", "id", id)
	return s, nil
}
