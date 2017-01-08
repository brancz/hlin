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

package pgp

import (
	"errors"
	"os"

	"golang.org/x/crypto/openpgp"
)

const (
	MessageType = "PGP MESSAGE"
)

var (
	InvalidMessageTypeError = errors.New("invalid message type")
)

type Keyring struct {
	keyringFilename string
}

func NewKeyring(f string) *Keyring {
	return &Keyring{
		keyringFilename: f,
	}
}

func (r *Keyring) FindKeys(shortKeyIds []string) ([]*openpgp.Entity, error) {
	var res []*openpgp.Entity

	entitylist, err := r.ReadKeyRing()
	if err != nil {
		return nil, err
	}

	for _, e := range entitylist {
		for _, k := range shortKeyIds {
			if e.PrimaryKey.KeyIdShortString() == k {
				res = append(res, e)
				break
			}
		}
	}

	return res, nil
}

func (r *Keyring) FindKey(shortKeyId string) (*openpgp.Entity, error) {
	entitylist, err := r.ReadKeyRing()
	if err != nil {
		return nil, err
	}

	for _, e := range entitylist {
		if e.PrimaryKey.KeyIdShortString() == shortKeyId {
			return e, nil
		}
	}

	return nil, errors.New("key does not exist in keyring")
}

func (r *Keyring) ReadKeyRing() (openpgp.EntityList, error) {
	keyringFileBuffer, err := os.Open(r.keyringFilename)
	if err != nil {
		return nil, err
	}

	defer keyringFileBuffer.Close()
	return openpgp.ReadKeyRing(keyringFileBuffer)
}
