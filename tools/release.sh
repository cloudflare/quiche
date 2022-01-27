#!/bin/bash

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <version>" >&2
    exit 1
fi

if [ -n "$(git status -s)" ]; then
    echo "Working directory is dirty."
    exit 2
fi

VERSION=$1

cargo package --package quiche

sed -i "0,/^version/ s/version = \"\(.*\)\"/version = \"$VERSION\"/" quiche/Cargo.toml
git add quiche/Cargo.toml
git commit -m $VERSION
git tag -a $VERSION -m "quiche $VERSION" --sign
