# https://cmake.org/cmake/help/latest/module/CMakeGraphVizOptions.html

# NOTE: Use at least CMake 3.18 as it has lots of graphviz improvements.

set(GRAPHVIZ_GENERATE_PER_TARGET OFF)
set(GRAPHVIZ_GENERATE_DEPENDERS OFF)
set(GRAPHVIZ_CUSTOM_TARGETS ON)
set(GRAPHVIZ_IGNORE_TARGETS
    "\\.a$"
    "\\.so$"
    # Linker flags given directly in target_link_libraries().
    "^-" 
    # Copied LKL files.
    "copy-files.*"
    # Unimportant targets.
    "Python::Interpreter"
    "copy-lkl"
    # Unused targets.
    "oesgx"
    "oelibcxx"
    "libcxxrt"
    "libcxx"
    "libunwind"
    "oesnmalloc"
    "oehostsock"
    "oehostepoll"
    "oehostfs"
    "oehostresolver"
    "oe_ptrace"
    "oehostverify"
    "host_verify"
    "oedebugrt"
    )
