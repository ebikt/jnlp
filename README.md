Very insecure JNLP launcher for KVM
===================================

This is replacement of `javaws` binary. It does not support all features of java web start,
as it is aimed to run KVM applications of BMC of (old) servers.

WARNING: this implementation purposefully **turns off all security measures**. So use it with
caution in closed environment.

Usage
-----

`jnlp.py [options] <jnlpfile>`

Options:
  * `java=` path to java binary
  * `unpack=` path to unpack200 binary (Part of java web start implementations, provided Linux binaries in this repository)
  * `propsjar=` path to PrintProps.jar (Prints java props for filtering jars with libraries, provided in this repository)
  * `debug=1` Enables debug (print debug information and do not delete downloaded files)
  * `temp=` location of temporary directory
  * `blacklist=` blacklist of unwanted jars (Some KVM works better with ommiting some jars from download, see source code for default).

You can specify `-` instead of *\<jnlpfile\>*. The file will be read from *stdin* then (i.e., can be piped to `jnlp.py`).

SSL/TLS
-------

The downloader may not work although all security measures are turned off. You may need to provide libssl implentation
with compile time flag `enable-weak-ssl-ciphers` which is disabled by default (at least on Debian).

Note: all server that I manage do not need this (yet, as of 2022-06-01) or do not provide compatible jnlp file.

Unpack200
---------
unpack200 is part of java web start imlementation. Binaries included here are from openjdk,
so to be GPL compiant: see openjdk source for source of these files. Every other file is
is original work, that is not copied from anywhere.
