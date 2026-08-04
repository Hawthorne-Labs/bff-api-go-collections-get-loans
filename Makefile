.PHONY: build test lint docker-build clean

APP_NAME = bff-api-go-collections-get-loans
BINARY_NAME = server

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/server/

test:
	go test -v -cover ./...

lint:
	golangci-lint run ./...

docker-build:
	docker build -t $(APP_NAME):dev .

clean:
	rm -f $(BINARY_NAME)
	go clean -cache
