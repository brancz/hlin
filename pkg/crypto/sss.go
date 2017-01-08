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

package crypto

import (
	"io"

	"github.com/codahale/sss"
)

type Share struct {
	X byte
	Y []byte
}

func (s *Share) Serialize(w io.Writer) error {
	_, err := w.Write([]byte{s.X})
	if err != nil {
		return err
	}

	_, err = w.Write(s.Y)
	return err
}

func DeserializeShare(r io.Reader) (*Share, error) {
	res := &Share{}
	buf := make([]byte, 1)

	_, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	res.X = buf[0]

	for {
		_, err := r.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		res.Y = append(res.Y, buf[0])
	}

	return res, nil
}

func Combine(shares []*Share) []byte {
	sharesMap := make(map[byte][]byte)

	for _, share := range shares {
		sharesMap[share.X] = share.Y
	}

	return sss.Combine(sharesMap)
}

func Split(secret []byte, threshold, numShares int) ([]*Share, error) {
	sharesMap, err := sss.Split(byte(numShares), byte(threshold), secret)
	if err != nil {
		return nil, err
	}

	i := 0
	shares := make([]*Share, numShares)
	for k, v := range sharesMap {
		shares[i] = &Share{X: k, Y: v}
		i++
	}

	return shares, nil
}
