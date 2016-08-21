# lamport-signatures-lua

This is an attempt to create a lamport signature scheme based off of the description given at https://gist.github.com/karlgluck/8412807 .

I chose to code this in Lua, because it is easy to read, and should be able to be ported to other languages relatively easy.

Currently, this version uses a **non-standard** hash function, that **needs to be replaced** with an appropriate cryptographic hash function. My suggestion would be to use SHA-3 [Keccak](http://keccak.noekeon.org/).

All comments, questions, and hate-mail are accepted.
