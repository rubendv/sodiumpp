sodiumpp
========

*This is a very preliminary version, do NOT expect it to be secure or use it for anything important.*

This library implements the C++ API of NaCl (which is described [here](http://nacl.cr.yp.to/)) with some small improvements on top of libsodium, as well as a high level API that takes care of nonce generation for you.

The `nonce<unsigned int sequentialbytes>` class provides a nonce that can be incremented and passed to box/unbox functions. It consists of a sequential part that is `sequentialbytes` bytes long, which is preceded by a constant part that takes up the rest of the bytes in the nonce. This constant part can be specified by the user or generated randomly.
The nonce class detects an overflow in the sequential part if it occurs and will throw an exception if you try to access the sequential part after this. This is important for security as a nonce should never be repeated for messages between the same two keypairs.
For convenience, `nonce8`, `nonce16`, `nonce32` and `nonce64` typedefs are defined where the number indicates the number of _bits_ (not bytes!) in the sequential part of the nonce.

The `boxer<typename noncetype>` and `unboxer<typename noncetype>` classes provide respectively box and unbox functionality


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
