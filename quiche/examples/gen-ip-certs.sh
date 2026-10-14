#!/bin/bash
# Generates the certificate fixtures needed to test IP-SAN verification.
set -ex
cd "$(dirname "$0")"
cat > ipext.cnf <<'CNF'
[ipsan]
basicConstraints=CA:FALSE
subjectAltName=IP:127.0.0.1,IP:0:0:0:0:0:0:0:1,DNS:quic.tech
[dnsonly]
basicConstraints=CA:FALSE
subjectAltName=DNS:127.0.0.1
[othersan]
basicConstraints=CA:FALSE
subjectAltName=IP:192.0.2.1
[nosan]
basicConstraints=CA:FALSE
CNF
openssl req -new -x509 -batch -nodes -days 3650 \
    -keyout iptest-ca.key -out iptest-ca.crt -subj '/C=GB/CN=ip-test-ca'
for n in ipsan dnsonly othersan; do
    openssl req -new -batch -nodes -sha256 -keyout iptest-$n.key \
        -out $n.csr -subj '/C=GB/CN=quic.tech'
    openssl x509 -req -days 3650 -in $n.csr -CA iptest-ca.crt \
        -CAkey iptest-ca.key -CAcreateserial -extfile ipext.cnf \
        -extensions $n -out iptest-$n.crt
    rm $n.csr
done
# CN=127.0.0.1 with no SAN: must NOT satisfy an IP-addressed connection.
openssl req -new -batch -nodes -sha256 -keyout iptest-cnonly.key \
    -out cnonly.csr -subj '/C=GB/CN=127.0.0.1'
openssl x509 -req -days 3650 -in cnonly.csr -CA iptest-ca.crt \
    -CAkey iptest-ca.key -CAcreateserial -extfile ipext.cnf \
    -extensions nosan -out iptest-cnonly.crt
rm cnonly.csr iptest-ca.key iptest-ca.srl ipext.cnf
