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

package config

import (
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	HostPort  string     `json:"hostPort"`
	TLS       bool       `json:"hostPort"`
	PGPConfig *PGPConfig `json:"pgpConfig"`
}

type PGPConfig struct {
	PublicKeyring string `json:"publicKeyring"`
	SecretKeyring string `json:"secretKeyring"`
	KeyId         string `json:"keyId"`
}

var (
	DefaultHostPort = "api.example.com:10000"

	DefaultPGPConfig = &PGPConfig{
		PublicKeyring: MustDefaultPublicKeyringFilePath(),
		SecretKeyring: MustDefaultSecretKeyringFilePath(),
	}

	DefaultConfig = &Config{
		HostPort:  DefaultHostPort,
		PGPConfig: DefaultPGPConfig,
	}

	DefaultConfigDirectoryName = ".hlin"
	DefaultConfigFilename      = "config.yaml"

	DefaultPGPDirectoryName         = ".gnupg"
	DefaultPGPPublicKeyringFilename = "pubring.gpg"
	DefaultPGPSecretKeyringFilename = "secring.gpg"
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
	if cfg.HostPort == "" {
		cfg.HostPort = DefaultHostPort
	}

	if cfg.PGPConfig == nil {
		cfg.PGPConfig = DefaultPGPConfig
	}

	if cfg.PGPConfig.PublicKeyring == "" {
		cfg.PGPConfig.PublicKeyring = MustDefaultPublicKeyringFilePath()
	}

	if cfg.PGPConfig.SecretKeyring == "" {
		cfg.PGPConfig.SecretKeyring = MustDefaultSecretKeyringFilePath()
	}
}

func (cfg *Config) SaveTo(file string) error {
	absFilepath, err := filepath.Abs(file)
	if err != nil {
		return err
	}

	d, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	dir, _ := filepath.Split(absFilepath)
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(absFilepath, d, 0644)
}

func MustDefaultConfigFilePath() string {
	fp, err := DefaultConfigFilePath()
	if err != nil {
		panic(err)
	}

	return fp
}

func DefaultConfigFilePath() (string, error) {
	cp, err := DefaultConfigPath()
	if err != nil {
		return "", err
	}

	return filepath.Join(cp, DefaultConfigFilename), nil
}

func DefaultConfigPath() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	return filepath.Join(u.HomeDir, DefaultConfigDirectoryName), nil
}

func MustDefaultPublicKeyringFilePath() string {
	fp, err := DefaultPublicKeyringFilePath()
	if err != nil {
		panic(err)
	}

	return fp
}

func DefaultPublicKeyringFilePath() (string, error) {
	cp, err := DefaultPGPPath()
	if err != nil {
		return "", err
	}

	return filepath.Join(cp, DefaultPGPPublicKeyringFilename), nil
}

func MustDefaultSecretKeyringFilePath() string {
	fp, err := DefaultSecretKeyringFilePath()
	if err != nil {
		panic(err)
	}

	return fp
}

func DefaultSecretKeyringFilePath() (string, error) {
	cp, err := DefaultPGPPath()
	if err != nil {
		return "", err
	}

	return filepath.Join(cp, DefaultPGPSecretKeyringFilename), nil
}

func DefaultPGPPath() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	return filepath.Join(u.HomeDir, DefaultPGPDirectoryName), nil
}
