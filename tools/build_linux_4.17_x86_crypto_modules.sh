#!/usr/bin/env bash

set -e

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

LINUX_4_17_COMMIT="29dcea8"

MODULES="\
arch/x86/crypto/aesni-intel.ko \
arch/x86/crypto/aes-x86_64.ko \
arch/x86/crypto/aesni-intel.ko \
arch/x86/crypto/chacha20-x86_64.ko \
arch/x86/crypto/poly1305-x86_64.ko \
arch/x86/crypto/salsa20-x86_64.ko \
arch/x86/crypto/serpent-avx-x86_64.ko \
arch/x86/crypto/serpent-avx2.ko \
arch/x86/crypto/sha1-ssse3.ko \
arch/x86/crypto/sha256-ssse3.ko \
arch/x86/crypto/sha512-ssse3.ko \
arch/x86/crypto/twofish-x86_64.ko \
arch/x86/crypto/twofish-x86_64-3way.ko \
arch/x86/crypto/twofish-avx-x86_64.ko"

usage() {
  echo "Usage: $0 <path-to-linux-kernel-source-tree> <path-to-output-dir>"
  exit 1
}

cleanup() {
  if [[ ! -z "${linux}" ]] && [[ -e "${linux}/.config.x86kmod.bck" ]]; then
    mv "${linux}/.config.x86kmod.bck" "${linux}/.config"
  fi

  if [[ ! -z "${linux}" ]] && [[ -e "${linux}/.x86kmod.patch" ]]; then
    rm "${linux}/.x86kmod.patch"
  fi

  if [[ ! -z "$APPLIED_PATCH" ]]; then
      git checkout include/linux/module.h
  fi

}

# This patch is needed so that the layout of struct module in the x86 build
# matches the layout in the LKL build. In particular the offsets of the fields
# 'name' and 'init' need to match.
create_modules_patch() {
cat << EOF > $1
diff --git a/include/linux/module.h b/include/linux/module.h
index d44df9b..cf26966 100644
--- a/include/linux/module.h
+++ b/include/linux/module.h
@@ -387,13 +387,6 @@ struct module {
        unsigned int num_exentries;
        struct exception_table_entry *extable;
 
-       /* Startup function. */
-       int (*init)(void);
-
-       /* Core layout: rbtree is accessed frequently, so keep together. */
-       struct module_layout core_layout __module_layout_align;
-       struct module_layout init_layout;
-
        /* Arch-specific module values */
        struct mod_arch_specific arch;
 
@@ -481,6 +474,15 @@ struct module {
        struct error_injection_entry *ei_funcs;
        unsigned int num_ei_funcs;
 #endif
+
+       uint64_t pad_lkl[1];
+
+       /* Startup function. */
+       int (*init)(void);
+
+       /* Core layout: rbtree is accessed frequently, so keep together. */
+       struct module_layout core_layout __module_layout_align;
+       struct module_layout init_layout;
 } ____cacheline_aligned __randomize_layout;
 #ifndef MODULE_ARCH_INIT
 #define MODULE_ARCH_INIT {}
EOF
}

trap cleanup EXIT

if [ $# -ne 2 ] ; then
  usage
  exit 1
fi

command -v git >/dev/null 2>&1 || { echo >&2 "git not available. Install with 'sudo apt-get install git'. Aborting."; exit 1; }

linux="`readlink -f "$1"`"
output="`readlink -f "$2"`"

echo "Changing directory to ${linux}..."
cd ${linux}
##if [[ `git status --porcelain` ]]; then
##  echo "The repository ${linux} has changes. Aborting..."
if [[ `git status --porcelain -- include/linux/module.h` ]]; then
  echo "The file include linux/module.h in repository ${linux} has changes. Aborting..."
  exit 1
fi

# TODO Check if current kernel version is based on 4.17 even if it has changes.
#echo "Checking out kernel version 4.17..."
#if ! git checkout ${LINUX_4_17_COMMIT}; then
#  echo "Failed to check out. Aborting..."
#  exit 1
#fi

if [[ -e "${linux}/.config" ]]; then
  mv "${linux}/.config" "${linux}/.config.x86kmod.bck"
fi

echo "Creating minimal x86 kernel config..."
cp "${ROOT_DIR}/linux_4.17_x86_crypto_modules.config" "${linux}/.config"

echo "Applying kernel patch to match LKL and x86 struct module..."
create_modules_patch "${linux}/.x86kmod.patch"
git apply --ignore-space-change --ignore-whitespace -v "${linux}/.x86kmod.patch"
APPLIED_PATCH=1

echo "Compiling x86 crypto kernel modules (writing log to make_x86kmod.log)..."
make clean && make $MODULES |& tee "${ROOT_DIR}/make_x86kmod.log"

echo "Copying kernel modules from ${linux}/arch/x86/crypto..."
mkdir -p  ${output}
cp -v ${linux}/arch/x86/crypto/*.ko ${output}

rm "${ROOT_DIR}/make_x86kmod.log"
