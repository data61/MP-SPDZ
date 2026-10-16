#!/usr/bin/env bash

function build
{
    echo ARCH = $1 >> CONFIG.mine
    echo GDEBUG = >> CONFIG.mine
    echo OTE_OPTS= -DENABLE_SOFTSPOKEN_OT=ON -DBUILD_SHARED_LIBS=0 -DCMAKE_INSTALL_LIBDIR=lib $3 >> CONFIG.mine
    rm -R deps/libOTe/out
    make clean
    rm -R static
    mkdir static
    make -j 4 static-release || exit 1
    mkdir bin
    dest=bin/`uname`-$2
    rm -R $dest
    mv static $dest
    strip $dest/*
}

make deps/libOTe/libOTe

echo AVX_OT = 1 >> CONFIG.mine
build '-msse4.1 -maes -mpclmul -mavx -mavx2 -mbmi2 -madx' adx -DENABLE_AVX=ON
