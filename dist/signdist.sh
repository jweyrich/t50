#!/bin/bash

if [ -z "$1" ]; then
  echo Usage: $0 filename
  exit 1
fi

gpg2 -sab "$1"
