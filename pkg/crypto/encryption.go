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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	pb "github.com/brancz/hlin/pkg/api/apipb"
)

var PGPMessageType = "PGP MESSAGE"

type EncryptionResult struct {
	CipherText *pb.CipherText
	Shares     *pb.Shares
}

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

type Participant interface {
	Encrypt(msg []byte) ([]byte, error)
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

func (p *X509Participant) Identifier() string {
	return p.cert.Subject.CommonName
}

type EncryptionScheme struct {
	encryptor    Encryptor
	participants []Participant
	threshold    int
	cipherText   io.Reader
	plainText    io.WriteCloser
	encWriter    io.WriteCloser
	result       *EncryptionResult
}

func NewEncryptionScheme(encryptor Encryptor, participants []Participant, numPublicShares, threshold int) (*EncryptionScheme, error) {
	cipherText := bytes.NewBuffer(nil)
	e := &EncryptionScheme{
		encryptor:    encryptor,
		participants: participants,
		threshold:    threshold,
		cipherText:   cipherText,
		result: &EncryptionResult{
			CipherText: &pb.CipherText{},
		},
	}

	var err error
	key := make([]byte, 32)

	_, err = rand.Read(key)
	if err != nil {
		return nil, err
	}

	e.result.Shares, err = SplitAndEncrypt(key, encryptor, participants, numPublicShares, threshold)
	if err != nil {
		return nil, err
	}

	e.encWriter, err = armor.Encode(cipherText, PGPMessageType, nil)
	if err != nil {
		return nil, err
	}

	e.plainText, err = openpgp.SymmetricallyEncrypt(e.encWriter, key, nil, nil)
	if err != nil {
		return nil, err
	}

	return e, nil
}

func SplitAndEncrypt(key []byte, encryptor Encryptor, participants []Participant, numPublicShares, threshold int) (*pb.Shares, error) {
	res := &pb.Shares{
		Public: &pb.PublicShares{
			Items: make([]*pb.PublicShare, numPublicShares),
		},
		Private: &pb.PrivateShares{
			Items: make([]*pb.PrivateShare, len(participants)),
		},
	}

	numShares := numPublicShares + len(participants)

	shares, err := Split(key, threshold, numShares)
	if err != nil {
		return nil, err
	}

	i := 0
	for j := 0; j < numPublicShares; j++ {
		publicShare, err := serializeShare(shares[i])
		if err != nil {
			return nil, err
		}

		publicShareSignature, err := encryptor.Sign(rand.Reader, publicShare, nil)
		if err != nil {
			return nil, err
		}

		res.Public.Items[j] = &pb.PublicShare{
			Content:   &pb.ByteContent{Bytes: publicShare},
			Signature: &pb.ByteContent{publicShareSignature},
			Signer:    encryptor.Identifier(),
		}
		i++
	}

	for k := range participants {
		b, err := serializeShare(shares[i])
		if err != nil {
			return nil, err
		}

		share, err := EncryptPrivateShare(encryptor, participants[k], b)
		if err != nil {
			return nil, err
		}

		res.Private.Items[k] = share
		i++
	}

	return res, nil
}

func EncryptPrivateShare(e Encryptor, p Participant, serializedShare []byte) (*pb.PrivateShare, error) {
	privateShare, err := p.Encrypt(serializedShare)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(privateShare)

	privateShareSignature, err := e.Sign(rand.Reader, h.Sum(nil), nil)
	if err != nil {
		return nil, err
	}

	return &pb.PrivateShare{
		Content:   &pb.ByteContent{privateShare},
		Signature: &pb.ByteContent{privateShareSignature},
		Receiver:  p.Identifier(),
		Signer:    e.Identifier(),
	}, nil
}

func (e EncryptionScheme) Encrypt(msg []byte) (*EncryptionResult, error) {
	_, err := e.plainText.Write(msg)
	if err != nil {
		return nil, err
	}
	e.plainText.Close()
	e.encWriter.Close()

	b, err := ioutil.ReadAll(e.cipherText)
	if err != nil {
		return nil, err
	}

	e.result.CipherText.Content = &pb.ByteContent{Bytes: b}
	return e.result, nil
}

func serializeShare(share *Share) ([]byte, error) {
	publicShare := bytes.NewBuffer(nil)

	err := share.Serialize(publicShare)
	if err != nil {
		return nil, err
	}

	return publicShare.Bytes(), nil
}

func Decrypt(encryptor Encryptor, cipherText []byte, shares *pb.Shares) (io.Reader, error) {
	key, err := DecryptSharesAndCombine(encryptor, shares)
	if err != nil {
		return nil, err
	}

	block, err := armor.Decode(bytes.NewBuffer(cipherText))
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

func DecryptSharesAndCombine(encryptor Encryptor, shares *pb.Shares) ([]byte, error) {
	var err error

	sssshares := make([]*Share, len(shares.Public.Items)+len(shares.Private.Items))
	i := 0

	for j := range shares.Public.Items {
		sssshares[i], err = DeserializeShare(bytes.NewBuffer(shares.Public.Items[j].Content.Bytes))
		if err != nil {
			return nil, err
		}
		i++
	}

	for k := range shares.Private.Items {
		plaintext, err := encryptor.Decrypt(shares.Private.Items[k].Content.Bytes)
		if err != nil {
			return nil, err
		}

		sssshares[i], err = DeserializeShare(bytes.NewBuffer(plaintext))
		if err != nil {
			return nil, err
		}
		i++
	}

	return Combine(sssshares), nil
}
