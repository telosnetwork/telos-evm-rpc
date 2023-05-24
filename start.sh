#!/bin/bash

INSTALL_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OG_DIR=`pwd`

cd $INSTALL_ROOT
npx tsc
pm2 start ./ecosystem.config.js
cd $OG_DIR