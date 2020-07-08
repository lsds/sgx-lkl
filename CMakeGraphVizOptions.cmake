# https://cmake.org/cmake/help/latest/module/CMakeGraphVizOptions.html

set(GRAPHVIZ_GENERATE_PER_TARGET OFF)
set(GRAPHVIZ_GENERATE_DEPENDERS OFF)
set(GRAPHVIZ_IGNORE_TARGETS
    "\\.a$"
    "\\.so$"
    "^-" # linker flags
    )
