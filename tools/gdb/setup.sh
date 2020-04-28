#!/usr/bin/env bash

set -e

OE_LIB_PATH=`pkg-config --variable libdir oeenclave-gcc`
OE_GDB_PLUGIN_DIR=$OE_LIB_PATH/openenclave/debugger
OE_GDB_PTRACE_PATH=$OE_GDB_PLUGIN_DIR/liboe_ptrace.so

cat > sgx-lkl-gdb <<EOF
#!/usr/bin/env bash

shopt -s expand_aliases

SGXLKL_GDB_PLUGIN=$(readlink -f ./sgx-lkl-gdb.py)
SGXLKL_GDB_COMMANDS=$(readlink -f ./gdbcommands.py)
OE_GDB_PLUGIN_PATH=$OE_GDB_PLUGIN_DIR/gdb-sgx-plugin
OE_GDB_PTRACE_PATH=$OE_GDB_PTRACE_PATH

if [ -f /usr/local/bin/gdb ]
then
    GDB=/usr/local/bin/gdb
elif [ -f /usr/bin/gdb ]
then
    GDB=/usr/bin/gdb
else
    GDB=gdb
fi

for arg in "\$@"
do
    if [[ \$arg = *"sgx-lkl-run-oe" ]]; then
        SGX_LKL_RUN=\$arg
        break
    fi
done

if [[ ! -z "\$SGX_LKL_RUN" ]]; then
    SGX_LKL_VERSION=\$(\$SGX_LKL_RUN --version)
    if [[ ! \$SGX_LKL_VERSION = *"DEBUG"* ]]; then
        echo "Warning: \$SGX_LKL_RUN not compiled with DEBUG=true. Debug symbols might be missing."
    fi
fi

export PYTHONPATH=\$OE_GDB_PLUGIN_PATH
LD_PRELOAD="\$OE_GDB_PTRACE_PATH" \$GDB -iex "directory \$OE_GDB_PLUGIN_PATH" -iex "set environment LD_PRELOAD" -iex "add-auto-load-safe-path /usr/lib" -iex "source \$OE_GDB_PLUGIN_PATH/gdb_sgx_plugin.py" -iex "source \$SGXLKL_GDB_PLUGIN" -iex "source \$SGXLKL_GDB_COMMANDS" "\$@"
EOF

chmod +x sgx-lkl-gdb
