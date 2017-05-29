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
	"crypto/tls"
	"crypto/x509"
	"io"
)

type Encryptor interface {
	crypto.Signer
	Identifier() string
	Decrypt([]byte) ([]byte, error)
}

type TLSEncryptor struct {
	TlsCert  tls.Certificate
	x509Cert *x509.Certificate
}

func LoadTLSEncryptor(certFile, keyFile string) (*TLSEncryptor, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	x509Cert, err := LoadX509Certificate(certFile)
	if err != nil {
		return nil, err
	}

	return NewTLSEncryptor(tlsCert, x509Cert), nil
}

func NewTLSEncryptor(tlsCert tls.Certificate, x509Cert *x509.Certificate) *TLSEncryptor {
	return &TLSEncryptor{
		TlsCert:  tlsCert,
		x509Cert: x509Cert,
	}
}

func (e *TLSEncryptor) Public() crypto.PublicKey {
	return e.TlsCert.PrivateKey.(*rsa.PrivateKey).Public()
}

func (e *TLSEncryptor) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return rsa.SignPSS(rand, e.TlsCert.PrivateKey.(*rsa.PrivateKey), crypto.SHA256, digest, nil)
}

func (e *TLSEncryptor) Decrypt(cipherText []byte) ([]byte, error) {
	return e.TlsCert.PrivateKey.(*rsa.PrivateKey).Decrypt(rand.Reader, cipherText, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte{}})
}

func (e *TLSEncryptor) Identifier() string {
	return e.x509Cert.Subject.CommonName
}
