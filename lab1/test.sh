#!/bin/bash
set -e

make debug

./server &

ps -p $! -o pid= &> /dev/null
if [ $? -ne 0 ]
then
    echo "Server failed to start!"
    exit 1
fi

./client
if [ $? -ne 0 ]
then
    echo "Client failed"
    exit 1
fi

killall server # For some reason, `kill %1` won't work?!

echo "smoke test passed. that deserves a smoke"
exit 0
