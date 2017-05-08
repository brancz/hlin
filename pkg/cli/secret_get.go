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
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/brancz/hlin/pkg/api/apipb"
	"github.com/brancz/hlin/pkg/client"
	"github.com/brancz/hlin/pkg/crypto"
)

type GetSecretCmdOptions struct {
	NoDecrypt bool
}

type secret struct {
	CipherText    *cipherText     `json:"cipherText,omitempty"`
	PublicShares  []*publicShare  `json:"publicShares,omitempty"`
	PrivateShares []*privateShare `json:"privateShares,omitempty"`
}

type cipherText struct {
	Content string `json:"content,omitempty"`
}

type publicShare struct {
	Content string `json:"content,omitempty"`
}

type privateShare struct {
	Content  string `json:"content,omitempty"`
	Receiver string `json:"receiver,omitempty"`
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
			conns := make([]*grpc.ClientConn, len(cfg.Members))
			for i, member := range cfg.Members {
				conn, err := client.NewConnection(ctx, member.HostPort, cfg.TLSConfig)
				if err != nil {
					log.Fatal(err)
				}
				defer conn.Close()
				conns[i] = conn
			}

			clients := make([]pb.APIClient, len(cfg.Members))
			for i, conn := range conns {
				clients[i] = pb.NewAPIClient(conn)
			}

			// TODO(brancz): try for all servers and use first successful response
			pubShares, err := clients[0].GetPublicShares(ctx, &pb.GetPublicSharesRequest{SecretId: args[0]})
			if err != nil {
				log.Fatalf("getting public shares failed: %s", err)
			}

			certificate, err := tls.LoadX509KeyPair(cfg.TLSConfig.CertFile, cfg.TLSConfig.KeyFile)
			privateKey := certificate.PrivateKey.(*rsa.PrivateKey)
			if err != nil {
				log.Fatal(err)
			}

			cert, err := crypto.LoadCertificate(cfg.TLSConfig.CertFile)
			if err != nil {
				log.Fatal(err)
			}

			privShares := []*pb.PrivateShare{}
			for _, client := range clients {
				privSharesRes, err := client.GetPrivateShares(ctx, &pb.GetPrivateSharesRequest{
					SecretId:  args[0],
					Requester: cert.Subject.CommonName,
				})
				if err != nil {
					log.Fatalf("getting private shares failed: %s", err)
				}
				privShares = append(privShares, privSharesRes.Items...)
			}

			// TODO(brancz): figure out better way for cipher text retrieval, proto
			// is probably not the ideal way for storage as secrets should be
			// unlimited size. Etcd values have an upper bound.
			ct, err := clients[0].GetCipherText(ctx, &pb.GetCipherTextRequest{SecretId: args[0]})
			if err != nil {
				log.Fatalf("getting cipher text failed: %s", err)
			}

			if options.NoDecrypt {
				s := &secret{
					CipherText:    &cipherText{Content: ct.Content},
					PublicShares:  []*publicShare{},
					PrivateShares: []*privateShare{},
				}

				for i := range pubShares.Items {
					s.PublicShares = append(s.PublicShares, &publicShare{Content: pubShares.Items[i].Content})
				}
				for i := range privShares {
					s.PrivateShares = append(s.PrivateShares, &privateShare{Content: base64.StdEncoding.EncodeToString([]byte(privShares[i].Content))})
				}

				j, err := json.Marshal(*s)
				if err != nil {
					log.Fatalf("json marshaling failed: %s", err)
				}

				out.Write(j)
				return
			}

			cipherText := bytes.NewBuffer([]byte(ct.Content))
			publicShares := make([]io.Reader, len(pubShares.Items))
			privateShares := make([]io.Reader, len(privShares))

			for i := range pubShares.Items {
				publicShares[i] = bytes.NewBuffer([]byte(pubShares.Items[i].Content))
			}
			for i := range privShares {
				privateShares[i] = bytes.NewBuffer([]byte(privShares[i].Content))
			}

			r, err := crypto.Decrypt(privateKey, cipherText, publicShares, privateShares)
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
