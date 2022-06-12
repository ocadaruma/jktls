#!/bin/bash

set -eu

cd "$(dirname $0)"

password="password"
keystore_file="src/main/resources/server.keystore.p12"
rm -f "$keystore_file"

keytool -genkey \
  -keystore "$keystore_file" \
  -alias localhost \
  -validity 36500 \
  -keyalg RSA \
  -storetype pkcs12 \
  -dname "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown" \
  -noprompt \
  -storepass "$password" \
  -keypass "$password"
