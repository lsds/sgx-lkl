New CMake-based build system
============================

The old hand-written GNU Make build system had several problems, notably:

 * Dependencies were not all tracked and so incremental builds sometimes failed in unexpected ways.
 * `make clean` did not clean everything.
 * The build system supported only in-tree builds.
 * The build system patched files in submodules, so submodules were never clean.
 * The build system encoded some of the layering violations, for example building the enclave as part of the musl build.
 * The logic to apply the wireguard patches to Linux is fragile.

The new build system has the following goals:

 * Full support for out-of-tree builds.
   The source tree should not be modified at all during the build process.
 * Parallel build support for all independent build steps.
 * Using Open Enclave's CMake support directly.
 * Support the fixed layering, building each component independently.



Overall design
--------------

The build system has to drive several other build systems of different kinds.
Some of these are submodules because they have some changes from upstream, others are downloaded as part of the build.
The downloaded tarballs are placed in the `downloads` directory and extracted into the `third_party` directory.

### LKL

The Linux kernel does not support out-of-tree builds and SGX-LKL needs to patch a small number of files in this build.
The build system copies the entire LKL tree into the build directory, patches it, and does an in-tree build.
The headers are installed in `lkl-headers/` in the build directory.
After the install step, the list of installed headers is stored in `lkl-headers.list` (writing to this file only if the list of headers has changed).
If this file has changed then CMake re-runs in the next build and adds this as outputs for the LKL build task, which ensures that anything implicitly depending on these files will be rebuilt if the files are modified.

We are building wireguard as part of Linux because we do not want to have to support modules.
After the wireguard tarball has been downloaded and extracted, we copy the two files that it modifies from the pristine source and then run the script that wireguard provides to patch the kernel sources.
If any of the patched files in the source tree or the wireguard tarball are modified, we delete the patched files and re-copy them.
This avoids the complex logic in the old build system for determining if the patch had been applied.


 
