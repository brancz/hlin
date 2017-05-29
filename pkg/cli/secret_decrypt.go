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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/brancz/hlin/pkg/api/apipb"
	"github.com/brancz/hlin/pkg/crypto"
)

func NewCmdSecretDecrypt(in io.Reader, out io.Writer) *cobra.Command {
	decryptSecretCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a secret",
		Long:  `Decrypt a secret.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := MustConfig()

			fi, err := os.Stdin.Stat()
			if err != nil {
				log.Fatal(err)
			}
			if fi.Mode()&os.ModeNamedPipe == 0 {
				log.Fatal("no data to read from stdin")
			}
			secret := apipb.CreateSecretRequest{}
			err = json.NewDecoder(os.Stdin).Decode(&secret)
			if err != nil {
				log.Fatal(err)
			}

			keyStore, err := crypto.KeyStoreFromConfig(cfg)
			if err != nil {
				log.Fatal(err)
			}

			r, err := crypto.Decrypt(keyStore, secret.CipherText.Content.Bytes, secret.Shares)
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

	return decryptSecretCmd
}
