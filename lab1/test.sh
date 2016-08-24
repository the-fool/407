#!/bin/bash
set -e

make debug || (cowsay "build FAIL!" && exit 1)

./server &

ps -p $! -o pid= &> /dev/null
if [ $? -ne 0 ]
then
    cowsay "Server FAILED to start!"
    exit 1
fi

./client
if [ $? -ne 0 ]
then
    cowsay "Client FAILED!"
    exit 1
fi

killall server # For some reason, `kill %1` won't work?!

cowsay "smoke test PASSED. that deserves a smoke"
exit 0
