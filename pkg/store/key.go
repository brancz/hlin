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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

var PublicKeyNotFound = errors.New("public key not found")

type KeyStore interface {
	PublicKey(identity string) (*rsa.PublicKey, error)
	PrivateKey() tls.Certificate
	Certificate() *x509.Certificate
}

type MemoryKeyStore struct {
	store   map[string]*rsa.PublicKey
	tlsCert tls.Certificate
	cert    *x509.Certificate
}

func NewMemoryKeyStore(store map[string]*rsa.PublicKey, tlsCert tls.Certificate, cert *x509.Certificate) KeyStore {
	return &MemoryKeyStore{
		store:   store,
		tlsCert: tlsCert,
		cert:    cert,
	}
}

func (s *MemoryKeyStore) PublicKey(identity string) (*rsa.PublicKey, error) {
	k, found := s.store[identity]
	if !found {
		return nil, PublicKeyNotFound
	}

	return k, nil
}

func (s *MemoryKeyStore) PrivateKey() tls.Certificate {
	return s.tlsCert
}

func (s *MemoryKeyStore) Certificate() *x509.Certificate {
	return s.cert
}
