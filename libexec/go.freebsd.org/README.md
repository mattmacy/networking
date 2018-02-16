# FreeBSD Go Usage Instructions

## Option 1: Augment `GOPATH`

The `GOPATH` environment variable accepts a colon (`:`) delimited list of
directories to search for Go files.  Set your `GOPATH` to include
`/usr/libexec/go.freebsd.org`.  For example:

```sh
export GOPATH=`go env GOPATH`:/usr/libexec/go.freebsd.org
```

## Option 2: Add `go.freebsd.org` to `GOPATH`'s hierarchy.

The other option is to simply symlink `go.freebsd.org` into `GOPATH`:

```
ln -sf /usr/libexec/go.freebsd.org `go env GOPATH`/src
# or if you're developing from src:
ln -sf /usr/src/libexec/go.freebsd.org `go env GOPATH`/src
```
