#!/usr/bin/env bash

HERE=$(cd `dirname $0`; pwd)
SPDZROOT=$HERE/..

export PLAYERS=2

. $HERE/run-common.sh

run_player yao-party.x $* || exit 1
