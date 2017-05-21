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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	pb "github.com/brancz/hlin/pkg/api/apipb"
	"github.com/brancz/hlin/pkg/client"
	"github.com/brancz/hlin/pkg/crypto"

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

			encryptor, err := crypto.LoadTLSEncryptor(cfg.TLSConfig.CertFile, cfg.TLSConfig.KeyFile)
			if err != nil {
				log.Fatal(err)
			}

			participants := make([]crypto.Participant, len(options.Receivers))
			for i := range options.Receivers {
				participants[i] = options.Receivers[i]
			}

			s, err := crypto.NewEncryptionScheme(
				encryptor,
				participants,
				options.PublicShares,
				options.Threshold,
			)
			if err != nil {
				log.Fatal(err)
			}
			res, err := s.Encrypt([]byte(plaintext))
			if err != nil {
				log.Fatal(err)
			}

			secret := &pb.CreateSecretRequest{
				CipherText: res.CipherText,
				Shares:     res.Shares,
			}

			ctx := context.TODO()
			conn, err := client.SingleConnectionFromConfig(ctx, cfg)
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
