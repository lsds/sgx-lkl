# Component CMake Scripts

This folder contains CMake files that build individual components of SGX-LKL.

Each component is exposed as one or more namespaced library targets.
Library targets are the main mechanism to refer to components in other parts of the build.

## Guidelines

### Naming

Library targets should be named `sgx-lkl::component` where the CMake script name is `component.cmake`.
If a component has multiple targets, it should use a suffix for each target.
This is not a strict rule but a recommendation to make finding target definitions easier for developers.

### Exposing variables

Components may expose variables for consumption in other components.
Typically variables are needed for driving external build systems where CMake targets cannot be used.

## Includes

Each component shall include *all* the CMake modules/scripts it needs.
