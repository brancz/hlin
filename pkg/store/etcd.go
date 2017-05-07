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
	pb "github.com/brancz/hlin/pkg/api/apipb"

	"github.com/coreos/etcd/clientv3"
	"github.com/go-kit/kit/log"
	proto "github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/context"
)

var SecretNotFound = errors.New("secret not found")
var SharesNotFound = errors.New("shares not found")
var CipherTextNotFound = errors.New("cipher text not found")

type SecretStore interface {
	CreateSecret(ctx context.Context, secretId string, s *pb.CreateSecretRequest) (*pb.PlainSecret, error)
	GetSecret(ctx context.Context, secretId string) (*pb.PlainSecret, error)
	GetPublicShares(ctx context.Context, secretId string) (*pb.PublicShares, error)
	GetPrivateShares(ctx context.Context, secretId, receiver string) (*pb.PrivateShares, error)
	GetCipherText(ctx context.Context, secretId string) (*pb.CipherText, error)
}

var WrongNumberOfResults = errors.New("incorrect number of results from etcd")

type EtcdStore struct {
	etcdclient *clientv3.Client
	logger     log.Logger
}

func NewEtcdStore(c *clientv3.Client, logger log.Logger) SecretStore {
	return &EtcdStore{
		etcdclient: c,
		logger:     logger,
	}
}

func (e *EtcdStore) CreateSecret(ctx context.Context, secretId string, s *pb.CreateSecretRequest) (*pb.PlainSecret, error) {
	ps := &pb.PlainSecret{SecretId: secretId}
	out, err := proto.Marshal(ps)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode PlainSecret")
	}

	_, err = e.etcdclient.Put(ctx, secretKey(secretId), string(out))
	if err != nil {
		return nil, errors.Wrap(err, "Secret could not be saved to etcd")
	}

	out, err = proto.Marshal(s.Shares.Public)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode PublicShare")
	}
	_, err = e.etcdclient.Put(ctx, publicSharesKey(secretId), string(out))
	if err != nil {
		return nil, errors.Wrap(err, "PublicShare could not be saved to etcd")
	}

	for _, share := range s.Shares.Private.Items {
		out, err = proto.Marshal(share)
		if err != nil {
			return nil, errors.Wrap(err, "failed to encode PublicShare")
		}
		_, err = e.etcdclient.Put(ctx, privateShareKey(secretId, share.Receiver, uuid.NewV4().String()), string(out))
		if err != nil {
			return nil, errors.Wrap(err, "PublicShare could not be saved to etcd")
		}
	}

	out, err = proto.Marshal(s.CipherText)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode CipherText")
	}
	_, err = e.etcdclient.Put(ctx, cipherTextKey(secretId), string(out))
	if err != nil {
		return nil, errors.Wrap(err, "CipherText could not be saved to etcd")
	}

	return ps, nil
}

func (e *EtcdStore) GetSecret(ctx context.Context, secretId string) (*pb.PlainSecret, error) {
	r, err := e.etcdclient.Get(ctx, secretKey(secretId))
	if err != nil {
		return nil, errors.Wrap(err, "getting secret from etcd failed")
	}

	if r.Count == 0 {
		return nil, SecretNotFound
	}
	if r.Count != 1 {
		return nil, WrongNumberOfResults
	}

	ps := &pb.PlainSecret{}
	err = proto.Unmarshal(r.Kvs[0].Value, ps)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling PlainSecret failed")
	}

	return ps, nil
}

func (e *EtcdStore) GetPublicShares(ctx context.Context, secretId string) (*pb.PublicShares, error) {
	r, err := e.etcdclient.Get(ctx, publicSharesKey(secretId))
	if err != nil {
		return nil, errors.Wrap(err, "getting PublicShares from etcd failed")
	}

	if r.Count == 0 {
		return nil, SharesNotFound
	}
	if r.Count != 1 {
		return nil, WrongNumberOfResults
	}

	pubShares := &pb.PublicShares{}
	err = proto.Unmarshal(r.Kvs[0].Value, pubShares)
	return pubShares, errors.Wrap(err, "unmarshaling PublicShares failed")
}

func (e *EtcdStore) GetPrivateShares(ctx context.Context, secretId, receiver string) (*pb.PrivateShares, error) {
	r, err := e.etcdclient.Get(ctx, privateSharesKeyForReceiver(secretId, receiver), clientv3.WithPrefix())
	if err != nil {
		return nil, errors.Wrap(err, "getting PrivateShares from etcd failed")
	}

	privShares := make([]*pb.PrivateShare, r.Count)
	for i, kv := range r.Kvs {
		privShare := &pb.PrivateShare{}
		err = proto.Unmarshal(kv.Value, privShare)
		if err != nil {
			return nil, errors.Wrap(err, "unmarshaling PrivateShare failed")
		}
		privShares[i] = privShare
	}

	return &pb.PrivateShares{
		Items: privShares,
	}, nil
}

func (e *EtcdStore) GetCipherText(ctx context.Context, secretId string) (*pb.CipherText, error) {
	r, err := e.etcdclient.Get(ctx, cipherTextKey(secretId))
	if err != nil {
		return nil, errors.Wrap(err, "getting CipherText from etcd failed")
	}

	if r.Count == 0 {
		return nil, CipherTextNotFound
	}
	if r.Count != 1 {
		return nil, WrongNumberOfResults
	}

	ct := &pb.CipherText{}
	err = proto.Unmarshal(r.Kvs[0].Value, ct)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling CipherText failed")
	}

	return ct, nil
}

func secretKey(secretId string) string {
	return "/secrets/" + secretId + "/secret"
}

func sharesKey(secretId string) string {
	return "/secrets/" + secretId + "/shares"
}

func publicSharesKey(secretId string) string {
	return sharesKey(secretId) + "/public"
}

func privateSharesKey(secretId string) string {
	return sharesKey(secretId) + "/private"
}

func privateSharesKeyForReceiver(secretId, receiver string) string {
	return privateSharesKey(secretId) + "/" + receiver
}

func privateShareKey(secretId, receiver, uuid string) string {
	return privateSharesKeyForReceiver(secretId, receiver) + "/" + uuid
}

func cipherTextKey(secretId string) string {
	return "/secrets/" + secretId + "/cipher_text"
}
