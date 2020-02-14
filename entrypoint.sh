#!/bin/bash

trap "exit 130" SIGINT
trap "exit 137" SIGKILL
trap "exit 143" SIGTERM

set -o nounset
set -o pipefail


main () {
  python3 /opt/scripts/build_config.py
  if [[ $? -ne 0 ]]
  then
      echo "Authorization failed; please verify CIF_HOST and CIF_TOKEN, then restart the container."
      echo "CIF_HOST=${CIF_HOST}"
      echo "CIF_TOKEN=${CIF_TOKEN}"
      sleep 120
      exit 1
  else
      echo "Successfully pinged CIF host with token"
  fi
  cat /opt/hpfeeds-cif.cfg
  python3 /opt/hpfeeds-cif/feedhandler.py /opt/hpfeeds-cif.cfg
}

main "$@"