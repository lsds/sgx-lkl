vicsetup (verity-integrity-crypt setup)
=======================================

**Vicsetup** is a tool for managing three kinds of dev-mapper devices:

    - dm-verity
    - dm-integrity
    - dm-crypt

Linux provides the following programs for managing these respectively:

    - veritysetup
    - integritysetup
    - cryptsetup

**Vicsetup** is an all-in-one replacement for these three Linux tools. It is
intended for use within the SGX-LKL enclave image and has various limitations
beyond this scope.

libvicsetup
===========

**Libvicsetup** provides features similar to **libcryptsetup.a**. the SGX-LKL
enclave image uses this library during setup (**src/lkl/setup.c**).

vicsetup
========

The **vicsetup** program is a test driver and provides similar capability to
veritysetup, integritysetup, and cryptsetup. It is limited and mainly intended
as a tool for testing **libvicsetup**.

libcryptsetup.h
===============

The **libcryptsetup.h** header provides a compatibility interface for making
integration easier with programs already using **libcryptsetup**. This header
only implements a subset of features (it implements only what is needed
by **src/lkl/setup.c**).

Building
========

To build everything, type:

```
make
```

To run tests, type:

```
make tests
```

To remove all output files, type:

```
make clean
```
