#!/bin/bash

dir="$(dirname $0)"
. "$dir"/run-common.sh
prog=${1%.sch}
prog=${prog##*/}
shift
mkdir logs 2> /dev/null
if test "$LOGPROT" = 1; then
    tee_opts=-a
    suffix=append-
fi
$prefix "$dir"/../emulate.x $prog $* -o print_compiler 2>&1 | tee $tee_opts logs/emulate-$suffix$prog
