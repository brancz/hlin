#!/usr/bin/env bash
set -er

echoerr() { echo "$@" 1>&2; }

if [ -z "$1" ]
then
  echoerr "Must specify version of protoc to install in form \"MAJOR.MINOR.PATCH\""
  exit 1
fi

version=$1

if [ -z "$2" ]
then
  install_dir=/usr/local
else
  install_dir=$2
fi

wget -O /tmp/protoc-${version}-linux-x86_64.zip https://github.com/google/protobuf/releases/download/v${version}/protoc-${version}-linux-x86_64.zip
unzip /tmp/protoc-${version}-linux-x86_64.zip -d /tmp/protobuf-${version}

cp /tmp/protobuf-${version}/bin/protoc ${install_dir}/bin/protoc
cp -r /tmp/protobuf-${version}/include/google ${install_dir}/include/google

go get github.com/gogo/protobuf/protoc-gen-gofast
