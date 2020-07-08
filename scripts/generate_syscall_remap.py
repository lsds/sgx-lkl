#!/usr/bin/python3

# This script is used to generate the fixup table mapping x86-64 syscalls
# onto their LKL equivalents.
#
# The output is part of src/misc/syscall.c in sgx-musl-lkl

LKL_UNISTD_PATH = "../lkl/tools/lkl/include/lkl/asm-generic/unistd.h"
NATIVE_TBL_PATH = "../lkl/arch/x86/entry/syscalls/syscall_64.tbl"


class Syscall:
    def __init__(self, name):
        self.name = name
        self.lkl_num = None
        self.native_num = None

    def __repr__(self):
        return "<{}: lkl{}, native{}>".format(self.name, self.lkl_num, self.native_num)


def parse_table(f, syscall_tab, attr):
    for ln in f:
        ln = ln.strip()
        if ln.startswith("#") or len(ln) == 0:
            continue
        num, abi, name, *extra = ln.split()
        if not abi == "common" and not abi == "64":
            continue
        num = int(num)
        if name not in syscall_tab:
            syscall_tab[name] = Syscall(name)
        setattr(syscall_tab[name], attr, num)


def parse_unistd(f, syscall_tab, attr):
    for ln in f:
        for prefix in ("#define __lkl__NR_", "#define __lkl__NR3264_"):
            if not ln.startswith(prefix):
                continue
            name, _, num = ln[len(prefix) :].strip().partition(" ")
            if name == "syscalls":
                # this is the syscall count!
                continue
            try:
                num = int(num)
            except ValueError:
                # we've probably reached the end...
                break
            if name not in syscall_tab:
                syscall_tab[name] = Syscall(name)
            setattr(syscall_tab[name], attr, num)
        for prefix in ("__LKL__SC_3264(__lkl__NR3264_",):
            if not ln.startswith(prefix):
                continue
            name, _, new_name = ln[len(prefix) :].strip().rstrip(")").split(", sys_")
            num = getattr(syscall_tab[name], attr)
            if new_name not in syscall_tab:
                syscall_tab[new_name] = Syscall(new_name)
            setattr(syscall_tab[new_name], attr, num)


syscall_tab = {}
with open(LKL_UNISTD_PATH, "r") as f:
    parse_unistd(f, syscall_tab, "lkl_num")
with open(NATIVE_TBL_PATH, "r") as f:
    parse_table(f, syscall_tab, "native_num")

syscall_nums = [
    f
    for f in syscall_tab.values()
    if f.native_num is not None and f.lkl_num is not None
]
syscall_nums.sort(key=lambda f: f.native_num)

print("static const short syscall_remap_len = {};".format(syscall_nums[-1].native_num))
print("static const short syscall_remap[] = {")
x = 0
for n in range(syscall_nums[-1].native_num + 1):
    if syscall_nums[x].native_num != n:
        print("\t-1, /* not implemented in x86-64 */")
        continue
    e = syscall_nums[x]
    print("\t{}, /* {} - x86-64 syscall: {} */".format(e.lkl_num, e.name, e.native_num))
    x += 1
print("};")
