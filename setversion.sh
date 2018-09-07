#!/bin/sh

if [ -z "$1" ]; then
cat <<@@
Usage: $(basename $0) version

Example:
  $ ./$(basename $0) 5.7.3
@@

  exit 1
fi

sed -i "s/PACKAGE_VERSION[ \t]\+\"\(.\+\)\"/PACKAGE_VERSION \"$1\"/" src/include/configuration.h
sed -i "s/^VERSION=\(.\+\)/VERSION=$1/" Makefile
