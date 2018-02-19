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
6. `go get -u -d github.com/sean-/seed`

## Testing

Run the VPC tests:

```
cd src/libexec/go.freebsd.org/sys/vpc
doas go test -v ./...
doas go test -bench . -benchtime 15s ./...
```

## Development

### Rapid Pull Loop

```sh
#!/bin/sh --

set -e

cd /usr/src
git pull
cd /usr/src
make -j`sysctl -n hw.ncpu` buildkernel KERNCONF=BHYVE -DNO_KERNELCLEAN -s COPTFLAGS=-O0
doas make installkernel KERNCONF=BHYVE
doas kldunload vmmnet
doas kldload vmmnet
cd /usr/src/libexec/go.freebsd.org/sys/vpc
doas go test ./...
```

### Debugging

- `doas truss -faDH go test ./...`

### Enabling `MemGuard(9)`

Add the following kernel option:

```
options         DEBUG_MEMGUARD
```

and install the new kernel.  Once restarted and up and running, enable
`MemGuard(9)` for `ifnet` or `vmmnet`.

```
$ doas sysctl vm.memguard.desc="ifnet"
$ doas sysctl vm.memguard.desc="vmmnet"
```

NOTE: It is required to enable this `sysctl(8)` *BEFORE* loading `vmmnet.ko`
below.

If a panic occurs during testing, `dump` a core and `reboot`.

#### TODO

- Build a series of scripts to trace execution
