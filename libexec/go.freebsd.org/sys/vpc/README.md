# Virtual Private Cloud ("VPC")

The Virtual Private Cloud ("VPC") system provides network isolation to bhyve
guests in a coherent way.

## Requirements

1. `vmmnet` must be loaded

## Testing

1. ```
ln -s /usr/libexec/go.freebsd.org `go env GOPATH`/src
```
2. `cd src/libexec/go.freebsd.org/sys/vpc`
3. `go test -v ./...`

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
go test ./...
```

### Debugging

1. TODO(seanc@): Build a series of scripts to trace execution
2. `doas truss -faDH go test ./...`
