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
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/brancz/hlin/pkg/cli/config"
)

type globalFlags struct {
	cfgFile string
}

var (
	GlobalFlags = &globalFlags{}
)

func New(in io.Reader, out, err io.Writer) *cobra.Command {
	cmds := &cobra.Command{
		Use:   "hlin",
		Short: fmt.Sprintf("Client application for hlin"),
		Long: fmt.Sprintf(`Client application for hlin.

Use hlin to securely share any secrets (files, strings, whatever you want).`),
	}

	initPersistentFlags(cmds)

	cmds.AddCommand(NewCmdVersion(out))
	cmds.AddCommand(NewCmdConfig(in, out))
	cmds.AddCommand(NewCmdSecret(in, out))

	return cmds
}

func initPersistentFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&GlobalFlags.cfgFile, "config", "c", config.MustDefaultConfigFilePath(), "config file to use")
}
