
gdb_front()
{
    prog=$1
    shift
    gdb $prog -ex "run $*"
}

gdb_screen()
{
    prog=$1
    shift
    IFS=
    name=$screen_prefix${*/-/}
    IFS=' '
    name=${name:0:70}
    screen -S :$name -d -m bash -l -c "echo $*; echo $LIBRARY_PATH; gdb $prog -ex \"run $*\""
}

valgrind_screen()
{
    prog=$1
    shift
    IFS=
    name=${*/-/}
    IFS=' '
    screen -S :$name -d -m bash -l -c "echo $*; echo $LIBRARY_PATH; valgrind $prog $*"
}

lldb_screen()
{
    prog=$1
    shift
    IFS=
    name=${*/-/}
    IFS=' '
    echo debug $prog with arguments $*
    echo name: $name
    tmp=/tmp/$RANDOM
    echo run > $tmp
    screen -S :$i -d -m bash -l -c "lldb -s $tmp $prog -- $*"
}

run_player() {
    port=${PORT:-$((RANDOM%10000+10000))}
    bin=$1
    shift
    prog=$1
    prog=${prog##*/}
    prog=${prog%.sch}
    shift
    if ! test -e logs; then
        mkdir logs
    fi
    params="$prog $* -pn $port -h localhost"
    if $SPDZROOT/$bin 2>&1 | grep -q '^-N,'; then
       params="$params -N $players"
    fi
    if test "$prog"; then
	log_prefix=$LOG_PREFIX$prog-
    fi
    if test "$LOGPROT"; then
	log_prefix=${log_prefix}single-
    fi
    if test "$BENCH" -o "$LOGPROT"; then
	log_prefix=$log_prefix$bin-$(echo "$*" | sed 's/ /-/g')-N$players-
    fi
    set -o pipefail
    for i in $(seq 0 $[players-1]); do
      if test "$GDB_PLAYER" -a $i = "$GDB_PLAYER"; then
	  my_prefix=gdb_front
      else
	  my_prefix=$prefix
      fi
      front_player=${GDB_PLAYER:-0}
      >&2 echo Running $my_prefix $SPDZROOT/$bin $i $params
      log=logs/$log_prefix$LOG_SUFFIX$i
      $my_prefix $SPDZROOT/$bin $i $params 2>&1 |
	  {
	      if test "$BENCH"; then
		  if test $i = $front_player; then tee -a $log; else cat >> $log; fi;
	      else
		  if test $i = $front_player; then tee $log; else cat > $log; fi;
	      fi
	  } &
      codes[$i]=$!
    done
    ctrlc()
    {
	pkill -P $$
    }
    trap ctrlc SIGINT
    for i in $(seq 0 $[players-1]); do
	if ! wait ${codes[$i]}; then
	    for i in $(seq 1 $[players-1]); do
		echo === Party $i
		tail -n 3 logs/$log_prefix$i
	    done
	    return 1
	fi
    done
}

getopts N: opt $(getopt N: $* 2>/dev/null)
if test "$opt" = N; then
    PLAYERS=$OPTARG
fi

players=${PLAYERS:-2}

SPDZROOT=${SPDZROOT:-.}

export LD_LIBRARY_PATH="$SPDZROOT:$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$SPDZROOT:$DYLD_LIBRARY_PATH"
