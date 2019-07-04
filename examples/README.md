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
You can experiment with [http3-client](http3-client.rs), [http3-server](http3-server.rs), [client](client.rs) and [server](server.rs) using Docker.

The Examples [Dockerfile](Dockerfile) builds a Debian image.

To build:

```
docker build -t cloudflare-quiche .
```

To run http3-client once the image is built:

```
docker run -it cloudflare-quiche
root@d137bc3a84f9:/usr/src# ./http3-client https://cloudflare-quic.com
```