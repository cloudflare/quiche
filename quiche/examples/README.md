How to build C examples
-----------------------

### Requirements

You will need the following libraries to build the C examples in this directory.
You can use your OS package manager (brew, apt, pkg, ...) or install them from
source.

- [libev](http://software.schmorp.de/pkg/libev.html)
- [uthash](https://troydhanson.github.io/uthash/)

### Build

Simply run `make` in this directory.

```
% make clean
% make
```

Examples Docker image
---------------------
You can experiment with [http3-client](http3-client.rs),
[http3-server](http3-server.rs), [client](client.rs) and [server](server.rs)
using Docker.

The Examples [Dockerfile](Dockerfile) builds a Debian image.

To build:

```
docker build -t cloudflare-quiche .
```

To make an HTTP/3 request:

```
docker run -it cloudflare-quiche http3-client https://cloudflare-quic.com
```
