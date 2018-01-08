miniroot
========

miniroot is a quick way of building a small Alpine disk image, appropriate for
use with sgx-musl.

There is a small set of packages which are installed by default at build time.
This package set is customizable by editing the buildenv.sh file located in
this directory and rebuilding.

Building
--------

To build `sgxlkl-miniroot-fs.img`, simply run `make` in this directory.
You'll need a working internet connection to install the packages.

If you've added more packages to `buildenv.sh`, you may need to increase the
size of `IMAGE_SIZE_MB` defined inside the Makefile, or the packages might
not fit inside the created disk image.

Running
-------

Using Redis as an example running on top of SGX-LKL:

```sh
SGXLKL_TAP=sgxlkl_tap0 SGXLKL_VERBOSE=1 ../../build/sgx-lkl-run ./sgxlkl-miniroot-fs.img /usr/bin/redis-server --bind 10.0.1.1
```

Once you see the ASCII-art Redis logo, you can talk to Redis using:

```sh
# On the host
redis-cli -h 10.0.1.1
```

as long as you have the Redis utilities installed. Install it with `sudo
apt-get install redis-tools` if needed.

