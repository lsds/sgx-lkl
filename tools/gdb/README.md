### How to setup and run:
The SGX-LKL gdb version has a dependancy on the OE SDK installation.

#### Source the openenclaverc file (Required)

Before the SGX-LKL gdb setup, you need to source the `openenclaverc` file to setup environment variables. The `openenclaverc` file can be found in the `share/openenclave` subdirectory of the OE SDK installation destination. 

You can use `.` in Bash to `source`:

```bash
. <package_installation_destination>/share/openenclave/openenclaverc
```

For example, if your package_installation_destination is /opt/openenclave:

```bash
. /opt/openenclave/share/openenclave/openenclaverc
```

#### Setup SGX-LKL gdb:

Create the SGX-LKL gdb wrapper (sgx-lkl-gdb), by running the following:

```bash
./setup.sh
```

#### Run sample application:

When running SGX-LKL, sgx-lkl-gdb supports the loading of new symbols from dynamic libraries that have been brought in by the SGX-LKL dynamic loader.

```bash
 SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1 LD_LIBRARY_PATH=/app:$LD_LIBRARY_PATH ./tools/gdb/sgx-lkl-gdb --args build/sgx-lkl-run-oe --hw-debug samples/basic/dynamic_loading/sgxlkl-disk.img /app/dynsymbols
```
