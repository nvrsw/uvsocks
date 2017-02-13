#!/bin/sh

MODULES="
  libuv
"

for m in $MODULES; do
  echo "update '$m'..."
  git submodule update --init $m
  [ -x $m/git-submodule-update.sh ] && (cd $m; ./git-submodule-update.sh)
done
