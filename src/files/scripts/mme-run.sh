#!/bin/bash

# Copyright 2019-present Open Networking Foundation
#
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

APPLICATION=$1

# copy config files to openmme target directly
case $APPLICATION in
    "s1ap-app")
      echo "Running mme-init script"
      /opt/mme/scripts/mme-init.sh
      ;;
    *)
      echo "Other interface"
      ;;
esac
        
cp /opt/mme/config/shared/* /openmme/target/conf/

cd /openmme/target
export LD_LIBRARY_PATH=/usr/local/lib:./lib

case $APPLICATION in
    "mme-app")
      echo "Starting mme-app"
      echo "conf/mme.json"
      cat conf/mme.json
      ./bin/mme-app
      ;;
    "s1ap-app")
      echo "Starting s1ap-app"
      echo "conf/s1ap.json"
      cat conf/s1ap.json
      ./bin/s1ap-app
      ;;
    "s6a-app")
      echo "Starting s6a-app"
      echo "conf/s6a.json"
      cat conf/s6a.json
      echo "conf/s6a_fd.conf"
      cat conf/s6a_fd.conf
      ./bin/s6a-app
      ;;
    "s11-app")
      echo "Starting s11-app"
      echo "conf/s11.json"
      cat conf/s11.json
      ./bin/s11-app
      ;;
    *)
      echo "invalid app $APPLICATION"
      ;;
esac
