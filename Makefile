.PHONY: build lint vet fmt test docker clean

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/frameio-auth  ./cmd/frameio-auth
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/frameio-relay ./cmd/frameio-relay

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...

lint: vet
	@unformatted=$$(gofmt -l cmd internal); \
	if [ -n "$$unformatted" ]; then \
		echo "ERROR: files not formatted with gofmt:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

test:
	go test ./...

docker:
	docker build -t frameio-immich-relay:latest .

clean:
	rm -rf bin
