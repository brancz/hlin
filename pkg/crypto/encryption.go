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
	"crypto/rand"
	"crypto/sha256"
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
		serializedShare, err := serializeShare(shares[i])
		if err != nil {
			return nil, err
		}

		publicShareSignature, err := encryptor.Sign(rand.Reader, serializedShare, nil)
		if err != nil {
			return nil, err
		}

		h := sha256.New()
		h.Write(serializedShare)
		hash := h.Sum(nil)

		res.Public.Items[j] = &pb.PublicShare{
			Content:   &pb.ByteContent{Bytes: serializedShare},
			Signature: &pb.ByteContent{Bytes: publicShareSignature},
			Hash:      &pb.ByteContent{Bytes: hash},
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
	h.Write(serializedShare)
	hash := h.Sum(nil)

	privateShareSignature, err := e.Sign(rand.Reader, hash, nil)
	if err != nil {
		return nil, err
	}

	return &pb.PrivateShare{
		Content:   &pb.ByteContent{privateShare},
		Signature: &pb.ByteContent{privateShareSignature},
		Hash:      &pb.ByteContent{hash},
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

func Decrypt(keyStore KeyStore, cipherText []byte, shares *pb.Shares) (io.Reader, error) {
	key, err := DecryptSharesAndCombine(keyStore, shares)
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

func DecryptSharesAndCombine(keyStore KeyStore, shares *pb.Shares) ([]byte, error) {
	var err error

	sssshares := make([]*Share, len(shares.Public.Items)+len(shares.Private.Items))
	i := 0

	for j := range shares.Public.Items {
		sssshares[i], err = VerifyPublicShare(keyStore, shares.Public.Items[j])
		if err != nil {
			return nil, err
		}
		i++
	}

	for k := range shares.Private.Items {
		sssshares[i], err = DecryptAndVerifyShare(keyStore, shares.Private.Items[k])
		if err != nil {
			return nil, err
		}
		i++
	}

	return Combine(sssshares), nil
}

func DecryptAndVerifyShare(keyStore KeyStore, s *pb.PrivateShare) (*Share, error) {
	plaintext, err := keyStore.Encryptor().Decrypt(s.Content.Bytes)
	if err != nil {
		return nil, err
	}

	p, err := keyStore.Participant(s.Signer)
	if err != nil {
		return nil, err
	}

	err = p.Verify(s.Signature.Bytes, s.Hash.Bytes)
	if err != nil {
		return nil, err
	}

	return DeserializeShare(bytes.NewBuffer(plaintext))
}

func VerifyPublicShare(keyStore KeyStore, s *pb.PublicShare) (*Share, error) {
	p, err := keyStore.Participant(s.Signer)
	if err != nil {
		return nil, err
	}

	err = p.Verify(s.Signature.Bytes, s.Hash.Bytes)
	if err != nil {
		return nil, err
	}

	return DeserializeShare(bytes.NewBuffer(s.Content.Bytes))
}
