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

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/brancz/hlin/pkg/pgp"
)

func Encrypt(encryptor *openpgp.Entity, participants []*openpgp.Entity, cipherText, publicShare io.Writer, privateShares []io.Writer, threshold int) (io.WriteCloser, io.Closer, error) {
	var err error

	key := make([]byte, 32)

	_, err = rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	encWriter, err := armor.Encode(cipherText, pgp.MessageType, nil)
	if err != nil {
		return nil, nil, err
	}

	plaintextWriter, err := openpgp.SymmetricallyEncrypt(encWriter, key, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	// 1 public share + n shares for each participant
	numShares := 1 + len(participants)

	shares, err := Split(key, threshold, numShares)
	if err != nil {
		return nil, nil, err
	}

	publicShareWriter := base64.NewEncoder(base64.StdEncoding, publicShare)
	if err != nil {
		return nil, nil, err
	}
	defer publicShareWriter.Close()

	err = shares[0].Serialize(publicShareWriter)
	if err != nil {
		return nil, nil, err
	}

	for i := range participants {
		err := encryptPrivateShare(privateShares[i], participants[i], encryptor, shares[1+i])
		if err != nil {
			return nil, nil, err
		}
	}

	return plaintextWriter, encWriter, nil
}

func encryptPrivateShare(privateShare io.Writer, participant, encryptor *openpgp.Entity, share *Share) error {
	privateShareWriter, err := armor.Encode(privateShare, pgp.MessageType, make(map[string]string))
	if err != nil {
		return err
	}

	plain, err := openpgp.Encrypt(privateShareWriter, []*openpgp.Entity{participant}, encryptor, nil, nil)
	if err != nil {
		return err
	}
	defer plain.Close()
	return share.Serialize(plain)
}

func Decrypt(entity *openpgp.Entity, cipherText, publicShare io.Reader, privateShares []io.Reader) (io.Reader, error) {
	var err error

	shares := make([]*Share, len(privateShares)+1)
	decodedPublicShare := base64.NewDecoder(base64.StdEncoding, publicShare)
	shares[0], err = DeserializeShare(decodedPublicShare)
	if err != nil {
		return nil, err
	}

	for i, privateShare := range privateShares {
		pf := openpgp.PromptFunction(func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			return nil, nil
		})

		block, err := armor.Decode(privateShare)
		if err != nil {
			return nil, err
		}
		if block.Type != pgp.MessageType {
			return nil, err
		}

		md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{entity}, pf, nil)
		if err != nil {
			return nil, err
		}

		shares[i+1], err = DeserializeShare(md.UnverifiedBody)
		if err != nil {
			return nil, err
		}
	}

	key := Combine(shares)
	block, err := armor.Decode(cipherText)
	if err != nil {
		return nil, err
	}
	if block.Type != pgp.MessageType {
		return nil, err
	}

	md, err := openpgp.ReadMessage(block.Body, nil, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return key, nil
	}, nil)
	if err != nil {
		return nil, err
	}

	return md.UnverifiedBody, nil
}
