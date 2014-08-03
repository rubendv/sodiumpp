sodiumpp
========

*This is a very preliminary version, do NOT expect it to be secure or use it for anything important.*

This library implements the C++ API of NaCl on top of libsodium, as well as a high level API that takes care of nonce generation for you:

```c++
#include "sodiumpp.h"
#include <string>
#include <iostream>
using namespace sodiumpp;

int main(int argc, const char ** argv) {
    box_secret_key sk_client;
    box_secret_key sk_server;

    // Uses predefined nonce type with 64-bit sequential counter and constant random bytes for the rest
    boxer<nonce64> client_boxer(sk_server.pk, sk_client);
    unboxer<nonce64> server_unboxer(sk_client.pk, sk_server, client_boxer.get_nonce_constant());

    encoded_bytes boxed = client_boxer.box("Hello, world!\n");
    std::string unboxed = server_unboxer.unbox(boxed);
    std::cout << unboxed;

    boxed = client_boxer.box("From sodiumpp!\n");
    unboxed = server_unboxer.unbox(boxed);
    std::cout << unboxed;
    return 0;
}
```
