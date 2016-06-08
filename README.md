sodiumpp
========

[![Build Status](https://travis-ci.org/rubendv/sodiumpp.svg?branch=master)](https://travis-ci.org/rubendv/sodiumpp)

*This is a very preliminary version, do NOT expect it to be secure or use it for anything important.*

This library implements the C++ API of NaCl (which is described [here](http://nacl.cr.yp.to/)) with some small improvements on top of libsodium, as well as a high level API that takes care of nonce generation for you.

Installation
------------

Building and installing is done using cmake:

```bash
mkdir build
cd build
cmake ..
make
make install
```

Example
-------

Compile this example by supplying the `-DSODIUMPP_EXAMPLE=1` flag to cmake, and run it with `./example`.

```c++
#include <sodiumpp/sodiumpp.h>
#include <string>
#include <iostream>
using namespace sodiumpp;

int main(int argc, const char ** argv) {
    box_secret_key sk_client;
    box_secret_key sk_server;

    std::cout << "Client key: " << sk_client << std::endl;
    std::cout << "Server key: " << sk_server << std::endl;
    std::cout << std::endl;

    // Uses predefined nonce type with 64-bit sequential counter 
    // and constant random bytes for the rest
    boxer<nonce64> client_boxer(sk_server.pk, sk_client);
    unboxer<nonce64> server_unboxer(sk_client.pk, sk_server, client_boxer.get_nonce_constant());

    nonce64 used_n;
    encoded_bytes boxed = client_boxer.box("Hello, world!\n", used_n);
    std::cout << "Nonce (hex): " << used_n.get(encoding::hex).bytes << std::endl;
    std::cout << "Boxed message (z85): " << boxed.to(encoding::z85).bytes << std::endl;
    // Nonce is passed explicitly here, but will also be increased automatically
    // if unboxing happens in the same order as boxing.
    // In a real application this nonce would be passed along with the boxed message.
    std::string unboxed = server_unboxer.unbox(boxed, used_n);
    std::cout << "Unboxed message: " << unboxed;
    std::cout << std::endl;

    boxed = client_boxer.box("From sodiumpp!\n", used_n);
    unboxed = server_unboxer.unbox(boxed, used_n);
    std::cout << "Nonce (hex): " << used_n.get(encoding::hex).bytes << std::endl;
    std::cout << "Boxed message (z85): " << boxed.to(encoding::z85).bytes << std::endl;
    std::cout << "Unboxed message: " << unboxed;
    return 0;
}
```

High-level API Overview
-----------------------

The `public_key<purpose P>` and `secret_key<purpose P>` are used to generate and store public and secret keys. Secret keys are locked into memory so they cannot be swapped out to disk, and are securely erased when the key's destructor is called. The template parameter `P` gives the purpose of the key: at the moment this is either `purpose::box` for box/unbox operations and `purpose::sign` for sign/verify operations. Having seperate types for public/secret keys and different purposes helps to avoid mixing them up.

The `nonce<unsigned int sequentialbytes>` class provides a nonce that can be incremented and passed to box/unbox functions. It consists of a sequential part that is `sequentialbytes` bytes long, which is preceded by a constant part that takes up the rest of the bytes in the nonce. This constant part can be specified by the user or generated randomly.
The nonce class detects an overflow in the sequential part if it occurs and will throw an exception if you try to access the sequential part after this. This is important for security as a nonce should never be repeated for messages between the same two keypairs.
For convenience, `nonce8`, `nonce16`, `nonce32` and `nonce64` typedefs are defined where the number indicates the number of _bits_ (not bytes!) in the sequential part of the nonce.

The `boxer<typename noncetype>` and `unboxer<typename noncetype>` classes provide respectively box and unbox functionality. They take a template argument `noncetype` which specifies the kind of nonce to use. The boxer will automatically increment the sequential part of the nonce for each message. Generated nonces will be even when the sender's public key is lexicographically smaller than the receiver's public key and uneven otherwise. This ensures that the other side can do the same thing without running the risk of using the same nonce for different messages between the same two keypairs, which would compromise the security of the messages. The unboxer will also automatically increment the nonce in the same manner, but an optional nonce override can be supplied at which point this overriding nonce is used instead of the current automatic nonce, and the current automatic nonce is left as-is. In a real system where ordering of the messages cannot be guaranteed the nonce that was used to box the message would be passed alongside the boxed message, and used as a nonce override at the unboxer side.

Throughout the API a string wrapper `encoded_bytes` is used, this stores a normal string alongside an encoding such as plain binary, hexadecimal or Z85 encoding to allow easy handling of strings in these encodings.

For more detailed API documentation, have a look at the comments in sodiumpp/include/sodiumpp/sodiumpp.h.
