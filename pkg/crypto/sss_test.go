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
	"bytes"
	"io/ioutil"
	"testing"
)

func TestEncryption(t *testing.T) {
	secrets := [][]byte{
		[]byte("exampleplaintext"),
		// handle further examples like ones that are not % 16 == 0
		// which needs padding to be handled correctly
	}

	for _, secret := range secrets {
		shares, err := Split(secret, 2, 3)
		if err != nil {
			t.Error(err)
		}

		combinations := [][]*Share{
			[]*Share{shares[0], shares[1]},
			[]*Share{shares[1], shares[2]},
			[]*Share{shares[0], shares[2]},
		}

		for _, combination := range combinations {
			plainText := Combine(combination)

			if !bytes.Equal(plainText, secret) {
				t.Error("decrypted plaintext does not match input secret")
			}
		}
	}
}

func TestShareDeserialization(t *testing.T) {
	r := bytes.NewBuffer([]byte("abc"))
	s, err := DeserializeShare(r)
	if err != nil {
		t.Error(err)
	}

	if s.X != byte('a') || !bytes.Equal(s.Y, []byte("bc")) {
		t.Error("Incorrectly deserialized")
	}
}

func TestShareSerialization(t *testing.T) {
	w := bytes.NewBuffer(nil)
	s := &Share{
		X: byte('a'),
		Y: []byte("bc"),
	}
	s.Serialize(w)

	res, err := ioutil.ReadAll(w)
	if err != nil {
		t.Error(err)
	}

	expected := "abc"
	result := string(res)
	if expected != result {
		t.Errorf("Incorrectly deserialized expected: %s got: %s", expected, result)
	}
}
