#!/bin/sh

# Thanks to the Fuchsia Authors for this!

case `uname` in
Linux)
    _N=`cat /proc/cpuinfo | grep processor | wc -l`
    N=`expr $_N + $_N`
    ;;
Darwin)
    N=`sysctl -n hw.ncpu`
    ;;
FreeBSD)
    N=`sysctl -n hw.ncpu`
    ;;
*)
    N=8
    ;;
esac

echo $N
