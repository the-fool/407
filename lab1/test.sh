#!/bin/bash
cleanup () {
  killall server
  killall client
}

make install || (echo ":: Build FAIL!" && exit 1)

./server &
ps -p $! -o pid= &> /dev/null
if [ $? -ne 0 ]
then
    echo ":: Server FAILED to start!"
    exit 1
fi

./client 127.0.0.1 &
ps -p $! -o pid= &> /dev/null
if [ $? -ne 0 ]
then
    echo ":: Client FAILED to start!"
    cleanup
    exit 1
fi

exit 0
