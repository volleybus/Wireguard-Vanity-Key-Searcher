# Wireguard-Vanity-Key-Searcher
A Python script to brute force Curve25519 Keys and search for a given string in its b64 encode.
## Setup
Python3 is required (f-strings <3). To install the package needed:


`pip install pynacl`
## Use 
I haven't yet added argparsing. For the time being edit the vars in the script end let it run.

You can adjust the multiprocess count to suit your needs. 

  'cpu_count - 1' seems to not hang the system and utilize ~100% of the cpu.
