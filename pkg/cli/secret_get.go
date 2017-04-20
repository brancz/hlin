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

package cli

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/brancz/hlin/pkg/api/apipb"
	"github.com/brancz/hlin/pkg/crypto"
	"github.com/brancz/hlin/pkg/pgp"
)

type jwt struct {
	token string
}

func (j jwt) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": j.token,
	}, nil
}

func (j jwt) RequireTransportSecurity() bool {
	// TODO(brancz): make this true once TLS is configurable
	return false
}

func NewCmdSecretGet(in io.Reader, out io.Writer) *cobra.Command {
	getSecretCmd := &cobra.Command{
		Use:   "get",
		Short: "Retrieve a secret from a server and decrypt it",
		Long:  `Retrieve a secret from a server and decrypt it.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := MustConfig()
			jwt := jwt{token: "test"}

			// TODO(brancz): make use of TLS configurable
			conn, err := grpc.Dial(
				cfg.HostPort,
				grpc.WithInsecure(),
				grpc.WithPerRPCCredentials(jwt),
			)
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()
			client := apipb.NewAPIClient(conn)

			secret, err := client.GetSecret(context.TODO(), &apipb.GetSecretRequest{SecretId: args[0]})
			if err != nil {
				log.Fatal(err)
			}

			entity, err := pgp.NewKeyring(cfg.PGPConfig.SecretKeyring).FindKey(cfg.PGPConfig.KeyId)
			if err != nil {
				log.Fatal(err)
			}

			cipherText := bytes.NewBuffer([]byte(secret.CipherText))
			publicShares := make([]io.Reader, len(secret.PublicShares))
			privateShares := make([]io.Reader, len(secret.PrivateShares))

			for i := range secret.PrivateShares {
				privateShares[i] = bytes.NewBuffer([]byte(secret.PrivateShares[i].Content))
			}
			for i := range secret.PublicShares {
				publicShares[i] = bytes.NewBuffer([]byte(secret.PublicShares[i].Content))
			}

			r, err := crypto.Decrypt(entity, cipherText, publicShares, privateShares)
			if err != nil {
				log.Fatal(err)
			}

			bytes, err := ioutil.ReadAll(r)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf(string(bytes))
		},
	}

	return getSecretCmd
}
