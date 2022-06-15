#!/bin/bash

set -ex

DIR=${1-$(pwd)}

CACERT="${DIR}/ca.cert"
CAKEY="${DIR}/ca.rsa"
KEY="${DIR}/end.rsa"
CERT="${DIR}/end.cert"
CHAIN="${DIR}/end.chain"

# cleanup
if [ -f "$CERT" ]; then  rm -f "$CERT"; fi
if [ -f "$KEY" ]; then rm -f "$KEY"; fi
if [ -f "$CACERT"]; then rm -f "$CACERT"; fi
if [ -f "$CAKEY"]; then rm -f "$CAKEY"; fi
if [ -f "$CHAIN"]; then rm -f "$CHAIN"; fi

# generate ca
openssl req -x509 -newkey rsa:2048 -days 3650 -keyout "$CAKEY" -out "$CACERT" -nodes -subj /CN=ca.testserver.com

# generate certs
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out "$CERT" -keyout "$KEY" -keyform P12 -subj /CN=testserver.com -config "${DIR}/openssl.cfg" -CA "$CACERT" -CAkey "$CAKEY"
# make key accessible #yolo
chmod 664 "$KEY"
# concat chain
cat "$CERT" "$CACERT" > "$CHAIN"