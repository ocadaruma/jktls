#!/bin/bash
set -e

version="$1"
if [ -z "$version" ]; then
    echo "Usage: $0 VERSION" >&2
    exit 1
fi

cd $(dirname $0)
cd core
../gradlew -Pversion=$version -Psnapshot=false clean universalJar

assetname="jktls-${version}-universal.jar"
filename="core-${version}-universal.jar"

curl --fail -L "https://github.com/ocadaruma/jktls/releases/download/v${version}/${assetname}" -o "build/libs/$filename"
echo -n "MD5 $filename: "
md5sum < "build/libs/$filename"

../gradlew -Pversion=$version -Psnapshot=false -x universalJar publish
