#!/bin/bash
set -e

# Script to make a new release.
# Upon successful CI, you need to execute maven-publish.sh next.

cd $(dirname $0)

version="$1"
if [ -z "$version" ]; then
    echo "Usage: $0 VERSION" >&2
    exit 1
fi

if [ $(git tag | grep "^v$version\$" | wc -l) -ne 0 ]; then
    echo "$version already released"
    exit 1
fi

sed -i "" -e "s/^version=.*$/version=$version/" ./gradle.properties

git add gradle.properties
git commit -m "Release $version"

git push origin master

tag="v$version"
git tag $tag
git push origin $tag
