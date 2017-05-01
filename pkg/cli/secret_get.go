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

type GetSecretCmdOptions struct {
	NoDecrypt bool
}

func NewCmdSecretGet(in io.Reader, out io.Writer) *cobra.Command {
	options := &GetSecretCmdOptions{}

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
				log.Fatalf("getting shares failed: %s", err)
			}

			ct, err := client.GetCipherText(ctx, &apipb.GetCipherTextRequest{SecretId: args[0]})
			if err != nil {
				log.Fatalf("getting cipher text failed: %s", err)
			}

			entity, err := pgp.NewKeyring(cfg.PGPConfig.SecretKeyring).FindKey(cfg.PGPConfig.KeyId)
			if err != nil {
				log.Fatalf("finding private key failed: %s", err)
			}

			if options.NoDecrypt {
				fmt.Fprintln(out, "CipherText: \n\n")
				fmt.Fprintln(out, ct.Content)
				for i := range shares.Public.Items {
					fmt.Fprintf(out, "\n\nPublicShare (%d): \n\n\n", i)
					fmt.Fprintln(out, shares.Public.Items[i].Content)
				}
				for i := range shares.Private.Items {
					fmt.Fprintf(out, "\n\nPrivateShare (%d): \n\n\n", i)
					fmt.Fprintln(out, shares.Private.Items[i].Content)
				}
				return
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
				log.Fatalf("decrypting secret failed: %s", err)
			}

			bytes, err := ioutil.ReadAll(r)
			if err != nil {
				log.Fatalf("reading the decrypted message failed: %s", err)
			}

			fmt.Printf(string(bytes))
		},
	}

	getSecretCmd.Flags().BoolVar(&options.NoDecrypt, "no-decrypt", false, "Do not decrypt the secret, instead print data to STDOUT")

	return getSecretCmd
}
