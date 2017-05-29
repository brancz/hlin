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

package crypto

import (
	"errors"

	"github.com/brancz/hlin/pkg/config"
)

var ParticipantNotFound = errors.New("participant not found")

type KeyStore interface {
	Participant(identifier string) (Participant, error)
	Encryptor() Encryptor
}

type MemoryKeyStore struct {
	store     map[string]Participant
	encryptor Encryptor
}

func KeyStoreFromConfig(cfg *config.Config) (KeyStore, error) {
	encryptor, err := LoadTLSEncryptor(cfg.TLSConfig.CertFile, cfg.TLSConfig.KeyFile)
	if err != nil {
		return nil, err
	}

	participants := make(map[string]Participant, len(cfg.Members))
	for _, member := range cfg.Members {
		p, err := LoadX509Participant(member.CertFile)
		if err != nil {
			return nil, err
		}
		participants[p.Identifier()] = p
	}
	return NewMemoryKeyStore(participants, encryptor), nil
}

func NewMemoryKeyStore(store map[string]Participant, encryptor Encryptor) KeyStore {
	return &MemoryKeyStore{
		store:     store,
		encryptor: encryptor,
	}
}

func (s *MemoryKeyStore) Participant(identifier string) (Participant, error) {
	p, found := s.store[identifier]
	if !found {
		return nil, ParticipantNotFound
	}

	return p, nil
}

func (s *MemoryKeyStore) Encryptor() Encryptor {
	return s.encryptor
}
