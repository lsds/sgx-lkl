Creating a patched Ubuntu Kernel with userspace FSGSBASE support
================================================================

The following instructions build a patched Ubuntu Bionic 18.04 HWE kernel. The current version of the kernel is:
```
$ uname -a
Linux msrc-cc06 5.3.0-40-generic #32~18.04.1 SMP Tue Mar 10 09:31:44 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

The FSGSBASE patch has been downloaded from (here)(https://lore.kernel.org/patchwork/series/412883/mbox/).

Such a patched kernel means that it is not longer necessary to use the unsafe FSGSBASE kernel module
(from tools/kmod-set-fsgsbase), which makes the kernel vulnerable to userspace processes.

1. Add the Ubuntu sources to apt-get: 
```
$ sudo sh -c 'echo "deb-src http://archive.ubuntu.com/ubuntu bionic main" >> /etc/apt/sources.list'
$ sudo sh -c 'echo "deb-src http://archive.ubuntu.com/ubuntu bionic-updates main" >> /etc/apt/sources.list'
```

2. Install the kernel build dependencies:
```
$ sudo apt-get update
$ sudo apt-get build-dep linux linux-image-unsigned-$(uname -r)
$ sudo apt-get install libncurses-dev flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf devscripts
```

3. Install the Ubuntu kernel source for the currently active kernel:
```
$ cd tools/ubuntu-kernel-patched-fsgsbase/
$ apt-get source linux-image-unsigned-$(uname -r)
```

4. Apply the FSGSBASE patch from the LKML:
```
$ cd linux-hwe-5.3.0
$ patch -p1 < ../Enable-FSGSBASE-instructions-v9.patch
```

This applies patch version 9.

5. Update the Debian package changelog to create a new kernel version:
```
$ debchange
```

Add the following entry to the changelog:
```
linux-hwe (5.3.0-40.32~18.04.1+fsgsbase) UNRELEASED; urgency=medium

  * Apply the FSGSBASE v9 patch from the LKML
```

6. Build the Ubuntu kernel packages:
```
$ fakeroot debian/rules binary
```

This step takes a long time.

7. Install the newly created patched Ubuntu kernel image:
```
$ cd ..
$ sudo dpkg -i --force-all linux-image-unsigned-5.3.0-40-generic_5.3.0-40.32~18.04.1+fsgsbase_amd64.deb linux-modules-5.3.0-40-generic_5.3.0-40.32~18.04.1+fsgsbase_amd64.deb linux-headers-5.3.0-40_5.3.0-40.32~18.04.1+fsgsbase_all.deb
```

The above command requires the `force` option to override the currently installed kernel. A better solution is to ensure that the new patched kernel has a different suffix.

8. Reboot the machine with the new kernel:
```
$ sudo reboot
```

Now FSGSBASE support should be available without relying on the FSGSBSE SGX-LKL kernel module.

To deactive FSGSBASE support, add the following kernel boot option: `nofsgsbase`
