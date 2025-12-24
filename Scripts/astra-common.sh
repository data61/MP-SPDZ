#!/usr/bin/env bash

HERE=$(cd `dirname $0`; pwd)
SPDZROOT=$HERE/..

killall $PROTOCOL-party.x $PROTOCOL-prep-party.x

for dir in Player-Data/3-$PROTOCOL-{{R,B}-64,2-{40,128}}; do
    mkdir $dir 2> /dev/null
    rm $dir/*
    for t in $(seq 0 100); do
	mkfifo $dir/{Protocol,Outputs}-{edaBits-,}P{0,1,2}-T$t
    done
done

export PLAYERS=3
export LOG_SUFFIX=prep-

. $HERE/run-common.sh

screen_prefix=p
run_player $PROTOCOL-prep-party.x $*  &


export PLAYERS=2
export LOG_SUFFIX=
export PORT=$[PORT+3]

. $HERE/run-common.sh

screen_prefix=
run_player $PROTOCOL-party.x $* || exit 1
