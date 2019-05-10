#!/bin/bash

m4 VERSION.m4 version_mod.m4 > ./.version
. ./.version

sed	\
    -e "s|@API_VERSION[@]|$API_VERSION|g" \
    -e "s|@NUM_VERSION[@]|$NUM_VERSION|g" \
    -e "s|@VERSION[@]|$VERSION|g"         \
    -e "s|@VENDOR_SUFFIX[@]|$VENDOR_SUFFIX|g" \
    -e "/@DEFAULT_PLUGINS[@]/r .DEFAULT_PLUGINS" \
    -e "/@DEFAULT_PLUGINS[@]/d" \
    ipapython/version.py.in > ipapython/version.py