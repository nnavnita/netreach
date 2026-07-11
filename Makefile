BINARY := netreach
PKG := ./...

.PHONY: build test lint run-example clean tidy

build:
	go build -o $(BINARY) ./cmd/netreach

test:
	go test -race -count=1 $(PKG)

lint:
	go vet $(PKG)
	gofmt -l . | tee /dev/stderr | (! read)

tidy:
	go mod tidy

run-example: build
	./$(BINARY) analyze --config testdata/simple.yaml --src eni-web --dst 1.1.1.1 --port 443 --protocol tcp

clean:
	rm -f $(BINARY)
