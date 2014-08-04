//
//  main.cpp
//  sodiumpp
//
//  Created by Ruben De Visscher on 02/08/14.
//  Copyright (c) 2014 Ruben De Visscher. All rights reserved.
//

#include <iostream>
#include <sodiumpp/sodiumpp.h>
#include <bandit/bandit.h>

using namespace sodiumpp;
using namespace bandit;

go_bandit([](){
    describe("z85", [](){
        box_secret_key box_sk;
        sign_secret_key sign_sk;
        
        it("can encode/decode box sk", [&](){
            encoded_bytes encoded = box_sk.get(encoding::z85);
            box_secret_key box_sk_decoded(box_sk.pk, encoded);
            AssertThat(box_sk_decoded.get().to_binary(), Equals(box_sk.get().to_binary()));
        });
        
        it("can encode/decode sign sk", [&](){
            encoded_bytes encoded = sign_sk.get(encoding::z85);
            sign_secret_key sign_sk_decoded(sign_sk.pk, encoded);
            AssertThat(sign_sk_decoded.get().to_binary(), Equals(sign_sk.get().to_binary()));
        });
    });
    
    describe("hex", [](){
        box_secret_key box_sk;
        sign_secret_key sign_sk;
        
        it("can encode/decode box sk", [&](){
            encoded_bytes encoded = box_sk.get(encoding::hex);
            box_secret_key box_sk_decoded(box_sk.pk, encoded);
            AssertThat(box_sk_decoded.get().to_binary(), Equals(box_sk.get().to_binary()));
        });
        
        it("can encode/decode sign sk", [&](){
            encoded_bytes encoded = sign_sk.get(encoding::hex);
            sign_secret_key sign_sk_decoded(sign_sk.pk, encoded);
            AssertThat(sign_sk_decoded.get().to_binary(), Equals(sign_sk.get().to_binary()));
        });
    });
});

int main(int argc, char ** argv) {
    return bandit::run(argc, argv);
}
