#!/bin/bash
set -ex
cd $(dirname $0)
openssl req -new -x509 -batch -nodes -days 10000 -keyout rootca.key -out rootca.crt
openssl req -new -batch -nodes -sha256 -keyout cert.key -out cert.csr -subj '/C=GB/CN=quic.tech'
openssl x509 -req -days 10000 -in cert.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out cert.crt
openssl verify -CAfile rootca.crt cert.crt
cp cert.crt cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
cat cert.crt >> cert-big.crt
rm cert.csr
rm rootca.key
rm rootca.srl

# required as rustls does not support v1 certificates
# rustls also needs the subjectAltName to successfully verify the certificates
echo '[v3_req]' > openssl.cnf
openssl req -new -x509 -batch -nodes -days 10000 -keyout rootca_rustls.key -out rootca_rustls.crt

openssl req -new -batch -nodes -sha256 -key cert.key -out cert_rustls.csr \
  -subj '/C=GB/CN=quic.tech'  -addext "subjectAltName=DNS:quic.tech"
openssl x509 -req -days 10000 -CAcreateserial -CA rootca_rustls.crt -CAkey rootca_rustls.key \
  -in cert_rustls.csr -out cert_rustls.crt -copy_extensions copyall
openssl verify -CAfile rootca_rustls.crt cert_rustls.crt
cat cert_rustls.crt cert_rustls.crt cert_rustls.crt cert_rustls.crt cert_rustls.crt > cert-big_rustls.crt

rm openssl.cnf
rm cert_rustls.csr
rm rootca_rustls.key
rm rootca_rustls.srl
