#!/bin/bash

INSTALL_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OG_DIR=`pwd`

cd $INSTALL_ROOT
pm2 stop ./ecosystem.config.js
cd $OG_DIR