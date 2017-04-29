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

package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	pb "github.com/brancz/hlin/pkg/api/apipb"
	"github.com/brancz/hlin/pkg/client"
	"github.com/brancz/hlin/pkg/crypto"
	"github.com/brancz/hlin/pkg/pgp"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

type CreateSecretCmdOptions struct {
	Threshold    int
	PublicShares int
	Plaintext    string
	Receivers    Receivers
}

func NewCmdSecretCreate(in io.Reader, out io.Writer) *cobra.Command {
	options := &CreateSecretCmdOptions{}

	createSecretCmd := &cobra.Command{
		Use:   "create",
		Short: "Encrypt and upload a secret",
		Long:  `Encrypt and upload a secret.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := MustConfig()

			plaintext := options.Plaintext
			fi, err := os.Stdin.Stat()
			if err != nil {
				log.Fatal(err)
			}
			if len(plaintext) == 0 && !(fi.Mode()&os.ModeNamedPipe == 0) {
				bytes, err := ioutil.ReadAll(os.Stdin)
				if err != nil {
					log.Fatal(err)
				}
				plaintext = strings.TrimSuffix(string(bytes), "\n")
			}
			if len(plaintext) == 0 {
				fmt.Fprintf(out, "Plain text: ")
				reader := bufio.NewReader(in)
				plaintext, _ = reader.ReadString('\n')
				plaintext = strings.TrimSuffix(plaintext, "\n")
			}

			encryptor, err := pgp.NewKeyring(cfg.PGPConfig.SecretKeyring).FindKey(cfg.PGPConfig.KeyId)
			if err != nil {
				log.Fatal(err)
			}

			participants, err := pgp.NewKeyring(cfg.PGPConfig.PublicKeyring).FindKeys(options.Receivers)
			if err != nil {
				log.Fatal(err)
			}

			cipherText := bytes.NewBuffer(nil)
			publicShares := make([]io.Writer, options.PublicShares)
			privateShares := make([]io.Writer, len(participants))
			for i := range publicShares {
				publicShares[i] = bytes.NewBuffer(nil)
			}
			for i := range privateShares {
				privateShares[i] = bytes.NewBuffer(nil)
			}

			plaintextWriter, closer, err := crypto.Encrypt(
				encryptor,
				participants,
				cipherText,
				publicShares,
				privateShares,
				options.Threshold,
			)
			if err != nil {
				log.Fatal(err)
			}
			plaintextWriter.Write([]byte(plaintext))

			plaintextWriter.Close()
			closer.Close()

			secret := &pb.CreateSecretRequest{
				CipherText: &pb.CipherText{
					Content: cipherText.String(),
				},
				Shares: &pb.Shares{
					Public: &pb.PublicShares{
						Items: make([]*pb.PublicShare, options.PublicShares),
					},
					Private: &pb.PrivateShares{
						Items: make([]*pb.PrivateShare, len(participants)),
					},
				},
			}

			for i := range publicShares {
				secret.Shares.Public.Items[i] = &pb.PublicShare{
					Content: publicShares[i].(*bytes.Buffer).String(),
				}
			}

			for i := range privateShares {
				secret.Shares.Private.Items[i] = &pb.PrivateShare{
					Content:  privateShares[i].(*bytes.Buffer).String(),
					Receiver: participants[i].PrimaryKey.KeyIdShortString(),
				}
			}

			ctx := context.TODO()
			conn, err := client.NewConnectionFromConfig(ctx, cfg)
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()
			client := pb.NewAPIClient(conn)

			ps, err := client.CreateSecret(ctx, secret)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(ps.SecretId)
		},
	}

	createSecretCmd.Flags().IntVarP(&options.Threshold, "threshold", "t", 2, "The threshold of how many shares have to be combined to reconstruct the secret. Must be equal to public-shares + number of receivers.")
	createSecretCmd.Flags().IntVarP(&options.PublicShares, "public-shares", "s", 1, "The amount of shares to generate to be available to all participants.")
	createSecretCmd.Flags().StringVarP(&options.Plaintext, "plaintext", "p", "", "The plaintext secret to encrypt and store.")
	createSecretCmd.Flags().VarP(&options.Receivers, "receiver", "r", "A receiver the secret shall be shared with (repeatable, defaults to none).")

	return createSecretCmd
}
