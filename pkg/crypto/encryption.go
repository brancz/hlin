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

func Encrypt(encryptor *openpgp.Entity, participants []*openpgp.Entity, cipherText io.Writer, publicShares, privateShares []io.Writer, threshold int) (io.WriteCloser, io.Closer, error) {
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

	numShares := len(publicShares) + len(privateShares)

	shares, err := Split(key, threshold, numShares)
	if err != nil {
		return nil, nil, err
	}

	i := 0
	for j := range publicShares {
		err := writePublicShare(publicShares[j], shares[i])
		if err != nil {
			return nil, nil, err
		}
		i++
	}

	for k := range participants {
		err := encryptPrivateShare(privateShares[k], participants[k], encryptor, shares[i])
		if err != nil {
			return nil, nil, err
		}
		i++
	}

	return plaintextWriter, encWriter, nil
}

func writePublicShare(publicShare io.Writer, share *Share) error {
	publicShareWriter := base64.NewEncoder(base64.StdEncoding, publicShare)
	defer publicShareWriter.Close()

	return share.Serialize(publicShareWriter)
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

func Decrypt(entity *openpgp.Entity, cipherText io.Reader, publicShares, privateShares []io.Reader) (io.Reader, error) {
	var err error

	shares := make([]*Share, len(publicShares)+len(privateShares))
	i := 0

	for j := range publicShares {
		decodedPublicShare := base64.NewDecoder(base64.StdEncoding, publicShares[j])
		shares[i], err = DeserializeShare(decodedPublicShare)
		if err != nil {
			return nil, err
		}
		i++
	}

	for k := range privateShares {
		pf := openpgp.PromptFunction(func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			return nil, nil
		})

		block, err := armor.Decode(privateShares[k])
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

		shares[i], err = DeserializeShare(md.UnverifiedBody)
		if err != nil {
			return nil, err
		}
		i++
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
