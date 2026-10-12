#!/usr/bin/env bash
# Generates throwaway lab certs into testserver/certs (gitignored). Requires OpenSSL >= 3.4 for -not_before/-not_after.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; D="$HERE/certs"; mkdir -p "$D"; cd "$D"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 -subj "/CN=webscan lab CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout good.key -out good.csr -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nauthorityKeyIdentifier=keyid\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" > san.ext
openssl x509 -req -in good.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out good.pem -days 30 -extfile san.ext 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout bad.key -out bad.pem -days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout exp.key -out exp.csr -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in exp.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out exp.pem -extfile san.ext -not_before 20250101000000Z -not_after 20250201000000Z 2>/dev/null || python3 "$HERE/make_expired.py"
echo "certs in $D"
