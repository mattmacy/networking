# Virtual Private Cloud ("VPC")

The Virtual Private Cloud ("VPC") system provides a cloud-natural experience for
bhyve guests.

## Requirements

1. `vmmnet(4)` must be loaded: `kldload /boot/modules/vmmnet.ko`
2. Add the VPC library to `GOPATH`:

    ```
% mkdir -p `go env GOPATH`/src
% ln -sf /usr/libexec/go.freebsd.org `go env GOPATH`/src
```

3. `go get -u -d github.com/pkg/errors`
4. `go get -u github.com/kylelemons/godebug/pretty`
5. `go get -u github.com/kylelemons/godebug/diff`

## Testing

Run the VPC tests:

    ```
cd src/libexec/go.freebsd.org/sys/vpc
go test -v ./...
```

## Development

### Rapid Pull Loop

```sh
#!/bin/sh --

set -e

cd /usr/src
git pull
cd /usr/src/sys/modules/vmmnet
make
doas make install
doas kldunload /boot/modules/vmmnet.ko
doas kldload /boot/modules/vmmnet.ko
cd /usr/src/libexec/go.freebsd.org/sys/vpc
doas go test ./...
```

### Debugging

- `doas truss -faDH go test ./...`

#### TODO

- Build a series of scripts to trace execution
