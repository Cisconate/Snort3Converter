Snort3Converter
===============

A project for converting IDS/IPS/NGFW rules into Snort 3 rules

:License: MIT License

Basic Commands
--------------

Running The Converter
^^^^^^^^^^^^^^^^^^^^^

* Arguments -
	REQUIRED ARGUMENTS::  input file, outputfile 
	
	OPTIONAL ARGUMENTS: SID starting # (default 1000000), input rule type (default SURRICATA), output rule type (default SNORT3)

* To run the tool via python::

    $ python snort3convert.py surricatarules.txt snort3rules.txt --SID 1000010 --source_rule_type SURRICATA --output_rule_type SNORT3
    
* To run the tool via windows executeable::

    $ snort3convert.exe surricatarules.txt snort3rules.txt --SID 1000010 --source_rule_type SURRICATA --output_rule_type SNORT3

For **convenience** you can use the defaults

* To run the short form of the above python command using defaults::

    $ python snort3convert.py surricatarules.txt snort3rules.txt
    
* To run the short form of the above windows comman using defaults::

    $ snort3convert.exe surricatarules.txt snort3rules.txt

Deployment
----------

The following details what modules are required.

Currently Built on Python 3.8, requires modules:

* re
* unidecode
* argparse
* time

