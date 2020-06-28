#!/bin/sh

# Thanks to the Fuchsia Authors for this!

case $(uname) in
Linux)
    _N=$(grep -c processor /proc/cpuinfo)
    N=$(( _N + _N ))
    ;;
Darwin)
    N=$(sysctl -n hw.ncpu)
    ;;
FreeBSD)
    N=$(sysctl -n hw.ncpu)
    ;;
*)
    N=8
    ;;
esac

echo $N
