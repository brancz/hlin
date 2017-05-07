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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var PGPMessageType = "PGP MESSAGE"

func Encrypt(participants []*x509.Certificate, cipherText io.Writer, publicShares, privateShares []io.Writer, threshold int) (io.WriteCloser, io.Closer, error) {
	var err error

	key := make([]byte, 32)

	_, err = rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	encWriter, err := armor.Encode(cipherText, PGPMessageType, nil)
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
		b := bytes.NewBuffer(nil)
		err := shares[i].Serialize(b)
		if err != nil {
			return nil, nil, err
		}

		encryptedShare, err := EncryptPrivateShare(participants[k].PublicKey.(*rsa.PublicKey), b.Bytes())
		if err != nil {
			return nil, nil, err
		}

		_, err = privateShares[k].Write(encryptedShare)
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

func EncryptPrivateShare(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		plaintext,
		[]byte{},
	)
}

func Decrypt(privKey *rsa.PrivateKey, cipherText io.Reader, publicShares, privateShares []io.Reader) (io.Reader, error) {
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
		b, err := ioutil.ReadAll(privateShares[k])
		if err != nil {
			return nil, err
		}

		plaintext, err := DecryptPrivateShare(privKey, b)
		if err != nil {
			return nil, err
		}

		shares[i], err = DeserializeShare(bytes.NewBuffer(plaintext))
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
	if block.Type != PGPMessageType {
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

func DecryptPrivateShare(privKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return privKey.Decrypt(rand.Reader, cipherText, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte{}})
}

func LoadCertificate(filename string) (*x509.Certificate, error) {
	rawCert, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pemCert, _ := pem.Decode(rawCert)
	return x509.ParseCertificate(pemCert.Bytes)
}
