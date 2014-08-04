sodiumpp
========

*This is a very preliminary version, do NOT expect it to be secure or use it for anything important.*

This library implements the C++ API of NaCl on top of libsodium, as well as a high level API that takes care of nonce generation for you:

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
