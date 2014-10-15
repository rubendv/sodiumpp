// Copyright (c) 2014, Ruben De Visscher
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <sodiumpp/sodiumpp.h>
#include <sodiumpp/serializer.h>
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

    std::stringstream ss;
    serializer<std::stringstream> s(ss);
    s.put<std::string>("Hello, world!").put<uint16_t>(2).put<uint16_t>(3).put<float>(3.14).put<int>(0xdeadbeef);
    std::cout << "Serialized message: " << encoded_bytes(ss.str(), encoding::binary).to(encoding::hex).bytes << std::endl;
    std::cout 
        << "Deserialized message: " 
        << s.get<std::string>() << " " 
        << s.get<uint16_t>() << " " 
        << s.get<uint16_t>() << " "
        << s.get<float>() << " "
        << "0x" << std::hex << s.get<int>() << std::endl;
    return 0;
}
