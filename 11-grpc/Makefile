BIN=$(shell realpath ./bin)

.PHONY: build
build:
	GOBIN=$(BIN) go install -v -race ./cmd/hash ./cmd/parhash

.PHONY: genproto
genproto: prototools
	protoc\
		--plugin ./bin/protoc-gen-go \
		--plugin ./bin/protoc-gen-go-grpc \
		-I./proto \
		--go_out=. \
		--go_opt=module=11-grpc \
		--go-grpc_out=. \
		--go-grpc_opt=module=11-grpc \
		--go-grpc_opt=require_unimplemented_servers=false \
		./proto/*.proto

.PHONY: prototools
prototools:
	GOBIN=$(BIN) go install \
		google.golang.org/protobuf/cmd/protoc-gen-go \
		google.golang.org/grpc/cmd/protoc-gen-go-grpc
