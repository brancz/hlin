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
	"errors"

	pb "github.com/brancz/hlin/pkg/api/apipb"

	"golang.org/x/net/context"
)

var SecretNotFound = errors.New("secret not found")
var SharesNotFound = errors.New("shares not found")
var CipherTextNotFound = errors.New("cipher text not found")

type Store interface {
	CreateSecret(ctx context.Context, secretId string, s *pb.CreateSecretRequest) (*pb.PlainSecret, error)
	GetSecret(ctx context.Context, secretId string) (*pb.PlainSecret, error)
	GetShares(ctx context.Context, secretId string) (*pb.Shares, error)
	GetCipherText(ctx context.Context, secretId string) (*pb.CipherText, error)
}
