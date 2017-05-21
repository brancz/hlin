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

package crypto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

var (
	rawCert = `-----BEGIN CERTIFICATE-----
MIIENjCCAh6gAwIBAgIRALI0U9Razeja2QTTW98KMBUwDQYJKoZIhvcNAQELBQAw
DTELMAkGA1UEAxMCY2EwHhcNMTcwNTE0MTUxNDAyWhcNMTkwNTE0MTUxNDAyWjAS
MRAwDgYDVQQDEwdzZXJ2ZXIwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA2kVo4R0duxbcuCaQmdmOe272WdHqhDLyS34nfK6lzUdEURPb48mpFk2s7yRX
9rC976G1uTXA3/2BH1Z4F+icjjYA3JycMQPkLhJNnv9B5rMKBrI2iDv8UOEy+50b
ja4SNYCroSR8wc+6eE3vmC8PDUiWpgH+v3/3Xrf/zPZG+wEBF3Is00UvED4pCP3Z
ktwt1LdfI5DeSioJPudLx9pMomM80IAc1ntaoD+9yD83iuqE/kpnJlQ2+Ll8FhO8
gqUZEmdKhT+KDovOqaDfK+vbwSEz6sXQwh+nbBBsymRtphuiBfdRc8NdDQRxTW9A
Uyol8XmzP//DWhu5eQWnrnJ7rwIDAQABo4GLMIGIMA4GA1UdDwEB/wQEAwIDuDAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFKb8JgTfTCsD
py/Cga3ZDED5LnvRMB8GA1UdIwQYMBaAFMMSrry9rBbh7BEeAhL7lVdYlpiEMBcG
A1UdEQQQMA6CDG15ZG9tYWluLmNvbTANBgkqhkiG9w0BAQsFAAOCAgEAmuiqL1wh
wYKOV2rENnq4+nV4do+KYOelRhv5T3wjr5SoOBY49ec7M9eFLlig1niIBO9vV5BD
TKlr0FGzpC6K11aPqcgu/b4neDmUThpLyGAgiBqqFFGfZStzkbkecUItw1wUFOjA
tefh+ZKQODnHL+XyPMGevTlbEIWGiCCLY50yttVjRtSer7N2ythNvbDdpgAyBtSj
6y01ZH/KS5/GAQoAmVw4xJibcBh/zNyk5lyIW67Xud+7ZJn8ZYNh8ZGTE6z2c3nX
fSsDgn++UXy46ZCTGPUoUrkenCXw4EzfuT0w4icV5E5/0B3H7lbvMmrwo/pZyLvX
WGryGfXEh7VIfC5gw9ddUKVVMZj4BbN9vr02xTWgaCdarGkpeD7VbnW5pvNwV/on
/A+FbhPcCL0osXnfiX9Hp+0o6gaRW7im6jDo+D7JRv+dVoHCt32w9K6Jsztz7BSR
Hyuyx5TLWqoT4aChKL/GT1jksG0/btIWZHonv4neMyOc1yplDQCLJPi7HrEdoCHo
wyP1H7yVI+GzlUxqImxNfj3vgzuYmjVqTFG9jD56VPAX/cQI0D71VqMyMpdRFlQN
5b/+b7DIZDQ2Qbz3erAo0xRRraTIm9iCJbALHjvLn8yyZIazt8n2LQAj1g0f+KHg
9K+11I9h1GZCc+mWRuSw9IoHxU6nEG7eJLA=
-----END CERTIFICATE-----`
	rawKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2kVo4R0duxbcuCaQmdmOe272WdHqhDLyS34nfK6lzUdEURPb
48mpFk2s7yRX9rC976G1uTXA3/2BH1Z4F+icjjYA3JycMQPkLhJNnv9B5rMKBrI2
iDv8UOEy+50bja4SNYCroSR8wc+6eE3vmC8PDUiWpgH+v3/3Xrf/zPZG+wEBF3Is
00UvED4pCP3Zktwt1LdfI5DeSioJPudLx9pMomM80IAc1ntaoD+9yD83iuqE/kpn
JlQ2+Ll8FhO8gqUZEmdKhT+KDovOqaDfK+vbwSEz6sXQwh+nbBBsymRtphuiBfdR
c8NdDQRxTW9AUyol8XmzP//DWhu5eQWnrnJ7rwIDAQABAoIBAQCo7SkjeGZHIoWG
XApzl6WnMBSnJUhMMiXFeYhT/dLCUdK0sRrwa2Vappkdp9IQUW9eY5gCFHEGqerh
9wkQ7+0iPvdhxi833Bwf7/h1AnbddllfH1QHEe3QJspPY6MsfrkHAWNTXqrTUNKv
QxoYfOs4S6KULl0blo07mEn4Ne5vWUQr5DRFH+qq3S2z2UIG2IXHcO5tR20eiJSZ
0KTQZYlkFehBMFUnBIoTb8W7LUYOTSwH1C74oulWww20BZNWrS0itF7olvCTdAku
dLYSjdH6lusq2DLrVYiEcUBEa/vnBPyHN7o/TgjTU1DP18OFbL72ubtY0AjiG+b8
LUr3aUUxAoGBAN+sgs1ESWVJCn79fxcmUtw8Oe/+ukwLoZ0QT+eGExc3ptIW6SzX
PR9x3Scf8mKajDG92qNuxmvOREs1BwQh6hVS0WS3o2NXjqSBlef+PJCwML/y0/xW
ar+MkhGw2sd9ck6BnOWWHXMABoplvhj4xhEksgyg4tmRzPUIVnyNmhhJAoGBAPnR
AhPUEaYUi9I3MGrLK0K6C5wk0uKBXqQaapl0VZoUoQI/PfagmBn7D4psWBx0g3ss
2i+nFydgCX2z00AyftKMdvmt53MpvUn2JYV2mO+4Mxe4wbSqfeWYyxXMTIAXuoOp
UVgXNIXU010CWTgfwYx6KdqvlxZ1r4/76Q8xhSQ3AoGATJfcasIZiA+NApN388tx
0GznQiGuVeAdxZUSZ6vn2al6/LJPwsUp7xykqIMuE0ns/BORTSnf1IbbqA1Oi8G5
UPf9MEoaLyiKdhbR6JGM19cdun1CzkQhZdqTIm+3W1y/ydZkjdHr37eAhd/1SsPV
v4UbW2u0guCEmNv0Ec7Dl9ECgYBYxCqfzxACWnSgWpnqqIyTpjXv4qnIcD2nw/cy
1cKBAGmBueUTmFbTjIEmJ39bhQ8fGn3gxteUVyyoLNiYjBjCScUQzPlb023+NOd6
N/z52RLWkADMaHRZu+QVt8VLEqNkmypbScuQ7mG4P9hh9+63MsViflgKVADxAYr7
qhXsGwKBgAwSp+QX5X+pwGQ/NHRfgxSWR5xFukaCwL/7edhQe6om0wkJR2YwbBng
zuxmq/IDSEnf4mh5PO7lHluL6xbH3GyKVZ/QWLgMpoF1GYhZMLtHmetA5pjfUyHt
bg9bvcD3a6l1FKNdI+DE/hTe7ApKEBpebkW8b9KvzrgbsaAOyVzu
-----END RSA PRIVATE KEY-----`
)

func makeTestTLSEncryptor() *TLSEncryptor {
	pemCert, _ := pem.Decode([]byte(rawCert))
	x509Cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		panic(err)
	}
	tlsCert, err := tls.X509KeyPair([]byte(rawCert), []byte(rawKey))
	if err != nil {
		panic(err)
	}

	return NewTLSEncryptor(tlsCert, x509Cert)
}

func makeTestX509Participant() *X509Participant {
	pemCert, _ := pem.Decode([]byte(rawCert))
	x509Cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		panic(err)
	}

	return NewX509Participant(x509Cert)
}

func makeTestParticipants() []Participant {
	return []Participant{
		makeTestX509Participant(),
		makeTestX509Participant(),
	}
}

func TestTLSEncryptor(t *testing.T) {
	p := makeTestX509Participant()
	e := makeTestTLSEncryptor()

	b, err := p.Encrypt([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	res, err := e.Decrypt(b)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res, []byte("test")) {
		t.Fatal("decrypted content is unequal the encrypted content")
	}
}

func TestEncryptionScheme(t *testing.T) {
	s, err := NewEncryptionScheme(
		makeTestTLSEncryptor(),
		makeTestParticipants(),
		0,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.Encrypt([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(
		makeTestTLSEncryptor(),
		res.CipherText.Content.Bytes,
		res.Shares,
	)
	if err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadAll(plaintext)
	if err != nil {
		t.Fatal("reading plaintext failed:", err)
	}

	if !bytes.Equal(b, []byte("test")) {
		t.Fatal("decrypted content is unequal the encrypted content")
	}
}

func TestShareCrypto(t *testing.T) {
	in := []byte("test")
	s, err := SplitAndEncrypt(
		in,
		makeTestTLSEncryptor(),
		makeTestParticipants(),
		0,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}

	out, err := DecryptSharesAndCombine(makeTestTLSEncryptor(), s)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out, in) {
		t.Fatalf("decrypted key is unequal the encrypted key\n\nExpected: %#+v\n\nGot: %#+v\n\n", in, out)
	}
}
