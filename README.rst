
============
wgvanitykey
============

A Python script to generate Curve25519 sk/pk keypairs and search for a
given string in the base64 encoding of the public key

.. contents::

Installation
=============
Requirements:

- Python3
- NaCL

To install the package:

.. code:: bash

    pip install -e git+https://github.com/volleybus/wgvanitykey#egg=wgvanitykey

Usage
=======

.. code:: bash

    Usage: wgvanitykey [-c <n>] [-m <startswith|contains>] <string>

    wgvanitykey -- generate Curve25519 sk/pk keypairs
    and search for a given string in the base64 encoding of the public key

    Usage::

        wgvanitykey -h
        wgvanitykey -c 1 test  # search for a pk that starts with 'test'
        wgvanitykey -c 1 test -m contains  # search for a pk that contains 'test'

    Options:
    -h, --help            show this help message and exit
    -c TARGETCOUNT, --targetcount=TARGETCOUNT
                            Generate this many keys before stopping (default: 5)
    -m MATCHMETHOD, --matchmethod=MATCHMETHOD
                            Method for selecting keys: startswith | contains
                            (default: startswith)
    -w WORKERCOUNT, --workercount=WORKERCOUNT
                            Number of workers to run. Setting this to greater than
                            the default cpu_count()-1 may cause the system to be
                            unresponsive
    -v, --verbose
    -q, --quiet
    -t, --test


License
=========
