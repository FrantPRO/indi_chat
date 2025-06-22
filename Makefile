build:
	go build -o bin/server ./cmd/server
	go build -o bin/client ./cmd/client

clean:
	rm -rf bin/

run-server:
	go run ./cmd/server

run-client:
	go run ./cmd/client -name $(NAME)

test:
	go test ./...

deps:
	go mod tidy

.PHONY: build clean run-server run-client test deps