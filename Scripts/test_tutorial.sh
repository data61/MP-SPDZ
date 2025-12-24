#!/usr/bin/env bash

while getopts XYC opt; do
    case $opt in
	X) compile_opts=-X
	   dabit=1
	   ;;
	Y) dabit=2
	   ;;
	C) cont=1
	   ;;
    esac
done

shift $[OPTIND-1]

for i in 0 1; do
    seq 0 3 > Player-Data/Input-P$i-0
done

# clean state
rm Player-Data/*Params*
rm Player-Data/*Secrets*

function test_vm
{
    ulimit -c unlimited
    vm=$1
    shift
    if ! Scripts/$vm.sh tutorial $* > /dev/null ||
	    ! grep 'weighted average: 2.333' logs/tutorial-0; then
	for i in $(seq 4 -1 0); do
	    echo == Party $i
	    cat logs/tutorial-$i
	done
	test -z $cont && exit 1
    fi
}

export PORT=$((RANDOM%10000+10000))
export BENCH=

for dabit in ${dabit:-0 1 2}; do
    if [[ $dabit = 1 ]]; then
	compile_opts="$compile_opts -X"
    elif [[ $dabit = 2 ]]; then
	compile_opts="$compile_opts -Y"
    fi

    ./compile.py -R 64 $compile_opts tutorial

    for i in ring rep4-ring semi2k sy-rep-ring spdz2k dealer-ring; do
	test_vm $i $run_opts
    done

    if test -z "$slim"; then
	for i in brain mal-rep-ring ps-rep-ring; do
	    test_vm $i $run_opts
	done
    fi

    test_vm rep4-ring $run_opts --semi-honest

    if test "$run_opts" != -F -a `uname` != Darwin; then
	./compile.py $compile_opts -E astra tutorial
	for i in astra trio; do
	    test_vm $i $run_opts
	done
    fi

    ./compile.py  $compile_opts tutorial

    for i in rep-field shamir sy-rep-field \
		       atlas mal-shamir sy-shamir hemi semi temi \
		       soho mascot; do
	test_vm $i $run_opts
    done

    if test -z "$slim"; then
	for i in mal-rep-field ps-rep-field mama; do
	    test_vm $i $run_opts
	done
    fi

    for i in cowgear chaigear; do
	test_vm $i $run_opts -S 3 -c 2
    done
done

if test $dabit != 0; then
    ./compile.py -R 64 -Z 3 tutorial
    test_vm ring $run_opts

    ./compile.py -R 64 -Z 4 tutorial
    test_vm rep4-ring $run_opts
    test_vm rep4-ring $run_opts --semi-honest

    ./compile.py -R 64 -Z ${PLAYERS:-2} tutorial
    test_vm semi2k $run_opts
fi

if test `uname` != Darwin -a -z "$run_opts"; then
    ./compile.py -E astra tutorial
    test_vm astra $run_opts
    test_vm trio $run_opts
fi

./compile.py tutorial

if test $no_top_gear; then
    for i in cowgear chaigear; do
	test_vm $i $run_opts -S 3 -c 2 -J
    done
fi

if test $skip_binary; then
   exit
fi

./compile.py -GB 16  $compile_opts tutorial

for i in replicated mal-rep-bin ps-rep-bin semi-bin ccd mal-ccd; do
    test_vm $i $run_opts
done

test_vm yao

for i in tinier rep-bmr mal-rep-bmr shamir-bmr mal-shamir-bmr; do
    test_vm $i $run_opts
done
