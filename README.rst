===================
Snort3Converter
===================

A project for converting IDS/IPS/NGFW rules into Snort 3 rules.

:License: MIT License

Basic Commands
--------------

Running The Converter
^^^^^^^^^^^^^^^^^^^^^

* Arguments -
	REQUIRED ARGUMENTS::  input file, outputfile 
	
	OPTIONAL ARGUMENTS: SID starting # (default 1000000), input rule type (default SURICATA), output rule type (default SNORT3)

* To run the tool via python

  .. code-block:: bash

    $ python snort3convert.py suricatarules.txt snort3rules.txt --SID 1000010 --source_rule_type SURICATA --output_rule_type SNORT3
    
* To run the tool via windows executeable

  .. code-block:: bash

    $ snort3convert.exe suricatarules.txt snort3rules.txt --SID 1000010 --source_rule_type SURICATA --output_rule_type SNORT3

For **convenience** you can use the defaults

* To run the short form of the above python command using defaults

  .. code-block:: bash

    $ python snort3convert.py suricatarules.txt snort3rules.txt
    
* To run the short form of the above windows command using defaults

  .. code-block:: bash

    $ snort3convert.exe suricatarules.txt snort3rules.txt

TESTED Supported Suricata Functions:
-------------------------------------

This tool has currently been tested on the following features:

============= ===============
Surricata Function Support Summary
-----------------------------
Feature       Support Status
============= ===============
URL           supported
SSH           supported
PCRE          supported
User-Agent    supported
============= ===============

==========================
Get Developing!
==========================

If you wish to contribute to expand support or simply hack away then plesae do!

Checkout the code:

.. code-block:: bash

   git clone http://github.com/RabidCicada/boardgame_framework

Install Dependencies:

.. code-block:: bash

    cd dev
    pip install requirements/dev.txt

==========================
To Generate the Docs
==========================
Install Dev Dependencies then:

.. code-block:: bash

    cd docs
    make

================
To Run the Tests
================

Quick and Dirty:

.. code-block:: bash

    $ cd src/
    $ python -m pytest ../tests
    or
    $ python -m pytest ../tests --log-cli-level DEBUG -s

The Right Way:

.. code-block:: bash

    $ tox

We use tox.  It builds virtual environments defined in tox.ini for different versions
of python, then builds the installable package, then installs it, then runs the tests.
It does this for all the versions you have defined and is suitable for continuous integration.

It is intentional that you cannot run a normal pytest command without PYTHONPATH
tomfoolery or calling pytest in the manner we show above for ``Quick and Dirty``.
By not being importable it prevents a whole class of testing problems related to accidentally
getting your local dev code instead of what is installed by the package.  It also forces you
in general to test installed code instead of dev code, making sure that your packaging is correct also


==========================
Frequently Asked Questions
==========================

1. Why this directory structure?
      https://blog.ionelmc.ro/2014/05/25/python-packaging/#the-structure
