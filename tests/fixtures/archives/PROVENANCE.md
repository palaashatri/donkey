# Archive fixtures

`libcheck.a` is a GNU `ar` (GNU Binutils 2.42) archive made from the two C sources
in this directory, with `cc -c -O0` and `ar rcs libcheck.a` for the two objects. Both
sources were written for this repository and carry no third-party code. The archive
has a symbol table, a long-name table and two members whose names need it, so it
exercises the System V and GNU name paths. The reader's output for it is checked
against `ar t` in `tests/CMakeLists.txt` (`cli.archive_list_gnu`).
