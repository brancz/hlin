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

	"github.com/brancz/hlin/pkg/api/apipb"
	"github.com/brancz/hlin/pkg/client"
	"github.com/brancz/hlin/pkg/crypto"
	"github.com/brancz/hlin/pkg/pgp"
)

func NewCmdSecretGet(in io.Reader, out io.Writer) *cobra.Command {
	getSecretCmd := &cobra.Command{
		Use:   "get",
		Short: "Retrieve a secret from a server and decrypt it",
		Long:  `Retrieve a secret from a server and decrypt it.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := MustConfig()

			ctx := context.TODO()
			conn, err := client.NewConnectionFromConfig(ctx, cfg)
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()
			client := apipb.NewAPIClient(conn)

			shares, err := client.GetShares(ctx, &apipb.GetSharesRequest{SecretId: args[0]})
			if err != nil {
				log.Fatal(err)
			}

			ct, err := client.GetCipherText(ctx, &apipb.GetCipherTextRequest{SecretId: args[0]})
			if err != nil {
				log.Fatal(err)
			}

			entity, err := pgp.NewKeyring(cfg.PGPConfig.SecretKeyring).FindKey(cfg.PGPConfig.KeyId)
			if err != nil {
				log.Fatal(err)
			}

			cipherText := bytes.NewBuffer([]byte(ct.Content))
			publicShares := make([]io.Reader, len(shares.Public.Items))
			privateShares := make([]io.Reader, len(shares.Private.Items))

			for i := range shares.Private.Items {
				privateShares[i] = bytes.NewBuffer([]byte(shares.Private.Items[i].Content))
			}
			for i := range shares.Public.Items {
				publicShares[i] = bytes.NewBuffer([]byte(shares.Public.Items[i].Content))
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
