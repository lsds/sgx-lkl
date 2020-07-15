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

Components *shall not* expose variables for public consumption.
Variables impose ordering constraints and are brittle.
Instead of variables, add custom properties on targets and use generator expressions to refer to them.

See `openenclave.cmake` and `edl.cmake` for an example where a custom target is used.
Note that custom targets cannot be namespaced.

See `musl.cmake` for an example where an `INTERFACE` library target is used.
Note that custom properties on `INTERFACE` targets need to be prefixed with `INTERFACE_`.

## Using helper functions and variables

Each component shall include *all* the CMake modules/scripts it needs.
These are typically built-in modules or files from the parent folder, like `RecursiveCopy.cmake`.

Note that a component script *shall not* include other component scripts.
Targets from other components are automatically available globally.
