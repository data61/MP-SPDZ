#!/bin/bash

make stream-fake-mascot-triples.x
./compile.py test_thread_mul || exit 1

rm Player-Data/2-p-128/Triples-p-P?-T?
mkdir Player-Data/2-p-128

for i in 0 1; do
    for j in 0 1 2; do
	mknod Player-Data/2-p-128/Triples-p-P$i-T$j p || exit 1
    done
done

./stream-fake-mascot-triples.x &
pid=$!

Scripts/mascot.sh test_thread_mul -f -o debug_file_signature || exit 1

kill $pid

./stream-fake-mascot-triples.x &

Scripts/mascot.sh test_thread_mul -f -o debug_file_signature || exit 1
