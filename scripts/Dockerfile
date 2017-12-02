FROM golang:1.9.2

ADD . /go/src/github.com/brancz/hlin

RUN apt-get update && apt-get install unzip && \
    /go/src/github.com/brancz/hlin/scripts/install-protobuf.sh 3.3.0 && \
    go get github.com/gogo/protobuf/protoc-gen-gofast

WORKDIR /go/src/github.com/brancz/hlin
