BINARY := osquery-cgroup.ext
GOFLAGS := -trimpath -ldflags="-s -w"

.PHONY: build test clean install

build:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BINARY) .

test:
	go test ./...

clean:
	rm -f $(BINARY)

install: build
	sudo cp $(BINARY) /opt/osquery/extensions/$(BINARY)
	sudo chown root:root /opt/osquery/extensions/$(BINARY)
	sudo chmod 755 /opt/osquery/extensions/$(BINARY)
