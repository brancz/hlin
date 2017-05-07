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

package config

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"
)

type Config struct {
	Members   Members    `json:"members"`
	TLSConfig *TLSConfig `json:"tlsConfig"`
}

type Members []*Member

type Member struct {
	HostPort string `json:"hostPort"`
	CertFile string `json:"certFile"`
}

type TLSConfig struct {
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	CaFile     string `json:"caFile"`
	ServerName string `json:"serverName"`
}

var (
	DefaultConfig = &Config{
		TLSConfig: &TLSConfig{},
	}

	DefaultConfigFilename = "config.yaml"
)

func FromFile(file string) (*Config, error) {
	cfg := &Config{}

	absFilepath, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(absFilepath); os.IsNotExist(err) {
		return DefaultConfig, nil
	}

	f, err := os.Open(absFilepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(b, cfg)
	if err != nil {
		return nil, err
	}

	setDefaults(cfg)

	return cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = &TLSConfig{}
	}
}
