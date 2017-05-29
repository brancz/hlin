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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

type Participant interface {
	Encrypt(msg []byte) ([]byte, error)
	Verify(signature, hash []byte) error
	Identifier() string
}

type X509Participant struct {
	cert *x509.Certificate
}

func LoadX509Certificate(certFile string) (*x509.Certificate, error) {
	rawCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	pemCert, _ := pem.Decode(rawCert)
	return x509.ParseCertificate(pemCert.Bytes)
}

func LoadX509Participant(certFile string) (*X509Participant, error) {
	cert, err := LoadX509Certificate(certFile)
	if err != nil {
		return nil, err
	}

	return NewX509Participant(cert), nil
}

func NewX509Participant(cert *x509.Certificate) *X509Participant {
	return &X509Participant{
		cert: cert,
	}
}

func (p *X509Participant) Encrypt(msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		p.cert.PublicKey.(*rsa.PublicKey),
		msg,
		[]byte{},
	)
}

func (p *X509Participant) Verify(signature, hash []byte) error {
	return rsa.VerifyPSS(
		p.cert.PublicKey.(*rsa.PublicKey),
		crypto.SHA256,
		hash,
		signature,
		nil,
	)
}

func (p *X509Participant) Identifier() string {
	return p.cert.Subject.CommonName
}
