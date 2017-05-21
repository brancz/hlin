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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/brancz/hlin/pkg/crypto"
)

type Receivers []*crypto.X509Participant

func (r *Receivers) String() string {
	return ""
}

func (r *Receivers) Set(value string) error {
	cert, err := crypto.LoadX509Certificate(value)
	if err != nil {
		return err
	}

	*r = append(*r, crypto.NewX509Participant(cert))
	return nil
}

func (r *Receivers) Type() string {
	return "map[string]*x509.Certificate"
}

type EncryptSecretCmdOptions struct {
	Threshold    int
	PublicShares int
	Plaintext    string
	Receivers    Receivers
}

func NewCmdSecretEncrypt(in io.Reader, out io.Writer) *cobra.Command {
	options := &EncryptSecretCmdOptions{}

	encryptSecretCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a secret",
		Long:  `Encrypt a secret.`,
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

			payload, err := json.Marshal(res)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Print(string(payload))
		},
	}

	encryptSecretCmd.Flags().IntVarP(&options.Threshold, "threshold", "t", 2, "The threshold of how many shares have to be combined to reconstruct the secret. Must be equal to public-shares + number of receivers.")
	encryptSecretCmd.Flags().IntVarP(&options.PublicShares, "public-shares", "s", 1, "The amount of shares to generate to be available to all participants.")
	encryptSecretCmd.Flags().StringVarP(&options.Plaintext, "plaintext", "p", "", "The plaintext secret to encrypt and store.")
	encryptSecretCmd.Flags().VarP(&options.Receivers, "receiver", "r", "A receiver the secret shall be shared with (repeatable, defaults to none).")

	return encryptSecretCmd
}
