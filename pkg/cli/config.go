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
	"log"
	"strings"

	"github.com/spf13/cobra"

	"github.com/brancz/hlin/pkg/cli/config"
)

type ConfigCmdOptions struct {
	PGPPublicKeyring string
	PGPSecretKeyring string
	PGPKeyId         string
	Url              string
}

func NewCmdConfig(in io.Reader, out io.Writer) *cobra.Command {
	options := &ConfigCmdOptions{}

	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configure this client",
		Long: `Configure this client to set which address to an API to use.

There are two ways to use this command. Interactively and non-interactively.

Interactively

	hlin config
	PGP Public Keyring: [/home/brancz/.gnupg/pubring.gpg] /home/brancz/.gnupg/pubring.gpg
	PGP Secret Keyring: [/home/brancz/.gnupg/secring.gpg] /home/brancz/.gnupg/secring.gpg
	PGP Key Id: [1E48B256] 1E48B256
	API Url: [https://api.example.com] https://api.example.com

Non-interactively

	hlin config --url https://api.example.com --public-keyring /home/brancz/.gnupg/pubring.gpg --secret-keyring /home/brancz/.gnupg/secring.gpg --key-id 1E48B256

`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := MustConfig()
			var err error

			if options.PGPPublicKeyring == "" {
				options.PGPPublicKeyring, err = Ask(in, out, "PGP Public Keyring:", cfg.PGPConfig.PublicKeyring)
				if err != nil {
					log.Fatal(err)
				}
			}

			if options.PGPSecretKeyring == "" {
				options.PGPSecretKeyring, err = Ask(in, out, "PGP Secret Keyring:", cfg.PGPConfig.SecretKeyring)
				if err != nil {
					log.Fatal(err)
				}
			}

			if options.PGPKeyId == "" {
				options.PGPKeyId, err = Ask(in, out, "PGP Key Id:", cfg.PGPConfig.KeyId)
				if err != nil {
					log.Fatal(err)
				}
			}

			if options.Url == "" {
				options.Url, err = Ask(in, out, "API Url:", cfg.BaseUrl)
				if err != nil {
					log.Fatal(err)
				}
			}

			cfg.PGPConfig.PublicKeyring = options.PGPPublicKeyring
			cfg.PGPConfig.SecretKeyring = options.PGPSecretKeyring
			cfg.PGPConfig.KeyId = options.PGPKeyId
			cfg.BaseUrl = options.Url

			cfg.SaveTo(GlobalFlags.cfgFile)
			fmt.Fprint(out, "\nClient configured.\n")
		},
	}

	configCmd.Flags().StringVarP(&options.Url, "url", "u", "", "The URL to use as a base URL when doing API requests.")
	configCmd.Flags().StringVarP(&options.PGPKeyId, "key-id", "k", "", "The PGP Key Id to use.")
	configCmd.Flags().StringVarP(&options.PGPPublicKeyring, "public-keyring", "p", "", "The PGP Public Keyring to use for public keys.")
	configCmd.Flags().StringVarP(&options.PGPSecretKeyring, "secret-keyring", "s", "", "The PGP Secret Keyring to use private keys.")

	return configCmd
}

func Ask(in io.Reader, out io.Writer, question, suggestedAnswer string) (string, error) {
	fmt.Fprint(out, question)
	if suggestedAnswer != "" {
		fmt.Fprintf(out, " [%s] ", suggestedAnswer)
	} else {
		// Print the space between question and answer
		fmt.Fprint(out, " ")
	}

	reader := bufio.NewReader(in)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	answer = strings.TrimSpace(answer)
	if answer == "" {
		return suggestedAnswer, nil
	}

	return answer, nil
}

func MustConfig() *config.Config {
	cfg, err := config.FromFile(GlobalFlags.cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	return cfg
}
