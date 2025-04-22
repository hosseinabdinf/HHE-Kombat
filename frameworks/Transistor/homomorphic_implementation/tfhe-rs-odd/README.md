This is the code for our custom version of tfhe-rs, forked from [https://github.com/zama-ai/tfhe-rs](). This holds the implementation of tfhe our transistor implementation is built on.


This is an extract of a much larger project and library. We tried to remove all stuffs that were not useful for this submission precisely.


Unlike the original library, this fork allows to manipulate plaintexts with **odd** modulus, which allows the implementation of `Transistor`.