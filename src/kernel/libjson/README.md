libjson
=======

This package defines a simple JSON parser library. Rather than building a
parse tree, it invokes a user-defined callback as elements are recognized
during parser.

Samples
=======

The **sample1** directory uses the parser to populate a multi-level C structure.

The **sample2** directory uses the parser to test JSON formatting.

The **jsonprint** sample formats JSON source and prints it to standard output.

Building
========

To build type 'make'. To clean type 'make clean'. The **libjson.a** library is
placed in the current directory.
