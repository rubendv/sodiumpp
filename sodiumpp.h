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

#ifndef sodiumpp_h
#define sodiumpp_h

#include <iostream>
extern "C" {
#include <sodium.h>
}

namespace sodiumpp {
    std::string crypto_auth(const std::string &m,const std::string &k);
    void crypto_auth_verify(const std::string &a,const std::string &m,const std::string &k);
    std::string crypto_box(const std::string &m,const std::string &n,const std::string &pk,const std::string &sk);
    std::string crypto_box_keypair(std::string *sk_string);
    std::string crypto_box_beforenm(const std::string &pk, const std::string &sk);
    std::string crypto_box_afternm(const std::string &m,const std::string &n,const std::string &k);
    std::string crypto_box_open(const std::string &c,const std::string &n,const std::string &pk,const std::string &sk);
    std::string crypto_box_open_afternm(const std::string &c,const std::string &n,const std::string &k);
    std::string crypto_hash(const std::string &m);
    std::string crypto_onetimeauth(const std::string &m,const std::string &k);
    void crypto_onetimeauth_verify(const std::string &a,const std::string &m,const std::string &k);
    std::string crypto_scalarmult_base(const std::string &n);
    std::string crypto_scalarmult(const std::string &n,const std::string &p);
    std::string crypto_secretbox(const std::string &m,const std::string &n,const std::string &k);
    std::string crypto_secretbox_open(const std::string &c,const std::string &n,const std::string &k);
    std::string crypto_sign_keypair(std::string *sk_string);
    std::string crypto_sign_open(const std::string &sm_string, const std::string &pk_string);
    std::string crypto_sign(const std::string &m_string, const std::string &sk_string);
    std::string crypto_stream(size_t clen,const std::string &n,const std::string &k);
    std::string crypto_stream_xor(const std::string &m,const std::string &n,const std::string &k);
    std::string crypto_shorthash(const std::string& m, const std::string& k);
    std::string randombytes(size_t size);
    
    std::string bin2hex(const std::string& bytes);
    std::string hex2bin(const std::string& bytes);
    void memzero(std::string& bytes);
    
    class crypto_error : public std::runtime_error {
    public:
        crypto_error(const std::string& what) : std::runtime_error(what) {}
    };
    
    enum class encoding {
        binary, hex
    };
    
    class public_key {
    private:
        std::string bytes;
        public_key() {}
    public:
        public_key(const std::string& bytes, encoding encoding=encoding::binary) {
            switch(encoding) {
                case encoding::binary:
                    this->bytes = bytes;
                    break;
                case encoding::hex:
                    this->bytes = hex2bin(bytes);
                    break;
            }
        }
        std::string get() const { return bytes; }
        friend class secret_key;
    };
    std::ostream& operator<<(std::ostream& stream, const public_key& pk);
    
    class secret_key {
    private:
        std::string secret_bytes;
    public:
        public_key pk;
        secret_key(const public_key& pk, const std::string& secret_bytes, encoding encoding=encoding::binary) : pk(pk) {
            switch(encoding) {
                case encoding::binary:
                    this->secret_bytes = secret_bytes;
                    break;
                case encoding::hex:
                    this->secret_bytes = hex2bin(secret_bytes);
                    break;
            }
        }
        secret_key() {
            pk.bytes = crypto_box_keypair(&secret_bytes);
        }
        std::string get() const { return secret_bytes; }
        ~secret_key() {
            memzero(secret_bytes);
        }
    };
    std::ostream& operator<<(std::ostream& stream, const secret_key& sk);

    class sign_public_key {
    private:
        std::string bytes;
    public:
        sign_public_key() {}
        sign_public_key(const std::string& bytes) : bytes(bytes) {}
        std::string get() const { return bytes; }
        friend class sign_secret_key;
    };

    class sign_secret_key {
    private:
        std::string secret_bytes;
    public:
        sign_public_key pk;
        sign_secret_key(const sign_public_key& pk, const std::string& secret_bytes) : pk(pk), secret_bytes(secret_bytes) {}
        sign_secret_key() {
            pk.bytes = crypto_sign_keypair(&secret_bytes);
        }
        std::string get() const { return secret_bytes; }
        ~sign_secret_key() {
            memzero(secret_bytes);
        }
    };
    
    template <unsigned int sequentialbytes>
    class nonce {
    private:
        static const unsigned int constantbytes = crypto_box_NONCEBYTES-sequentialbytes;
        std::string bytes;
        bool overflow;
    public:
        static_assert(sequentialbytes <= crypto_box_NONCEBYTES and sequentialbytes > 0, "sequentialbytes needs to smaller than crypto_box_NONCEBYTES and greater than 0");
        nonce() : nonce(""), overflow(false) {}
        nonce(const std::string& constant, bool uneven) : bytes(constant), overflow(false) {
            if(constant.size() > 0 and constant.size() != constantbytes) {
                throw "constant bytes does not have correct length";
            }
            bytes.resize(crypto_box_NONCEBYTES, 0);
            if(constant.size() == 0) {
                randombytes_buf(&bytes[0], constantbytes);
            }
            if(uneven) {
                bytes[bytes.size()-1] = 1;
            }
        }
        void increase() {
            unsigned int carry = 2;
            for(int64_t i = bytes.size()-1; i >= constantbytes && carry > 0; --i) {
                unsigned int current = *reinterpret_cast<unsigned char *>(&bytes[i]);
                current += carry;
                *reinterpret_cast<unsigned char *>(&bytes[i]) = current & 0xff;
                carry = current >> 8;
            }
            if(carry > 0) {
                overflow = true;
            }
        }
        std::string next() {
            increase();
            return get();
        }
        std::string get() const {
            if(overflow) {
                throw std::overflow_error("Sequential part of nonce has overflowed");
            } else {
                return bytes;
            }
        }
        std::string constant() const { return bytes.substr(0, constantbytes); }
        std::string sequential() const { return bytes.substr(constantbytes, sequentialbytes); }
    };
    
    typedef nonce<8> nonce64;
    typedef nonce<4> nonce32;
    typedef nonce<2> nonce16;

    template <unsigned int sequentialbytes>
    std::ostream& operator<<(std::ostream& s, nonce<sequentialbytes> n) {
        s << bin2hex(n.constant()) << " - " << bin2hex(n.sequential());
        return s;
    }
    
    template <typename noncetype>
    class boxer {
    private:
        noncetype n;
        std::string k;
        public_key pk;
        secret_key sk;
    public:
        boxer(const public_key& pk, const secret_key& sk) : boxer(pk, sk, "") {}
        boxer(const public_key& pk, const secret_key& sk, const std::string& nonce_constant) : pk(pk), sk(sk), k(crypto_box_beforenm(pk.get(), sk.get())), n(nonce_constant, sk.pk.get() > pk.get()) {}
        std::string nonce_constant() const { return n.constant(); }
        std::string box(std::string message) {
            std::string c = crypto_box_afternm(message, n.next(), k);
            //std::cout << "box(" << n << ", " << bin2hex(message) << ") = " << bin2hex(c) << std::endl;
            return c;
        }
        ~boxer() {
            memzero(k);
        }
    };
    
    template <typename noncetype>
    class unboxer {
    private:
        noncetype n;
        std::string k;
        public_key pk;
        secret_key sk;
    public:
        unboxer(const public_key& pk, const secret_key& sk, const std::string& nonce_constant) : pk(pk), sk(sk), k(crypto_box_beforenm(pk.get(), sk.get())), n(nonce_constant, pk.get() > sk.pk.get()) {}
        std::string nonce_constant() const { return n.constant(); }
        std::string unbox(std::string ciphertext) {
            std::string m = crypto_box_open_afternm(ciphertext, n.next(), k);
            //std::cout << "unbox(" << n << ", " << bin2hex(ciphertext) << ") = " << bin2hex(m) << std::endl;
            return m;
        }
        std::string unbox(std::string ciphertext, std::string sequentialpart) const {
            std::string m = crypto_box_open_afternm(ciphertext, n.constant() + sequentialpart, k);
            //std::cout << "unbox(" << n << ", " << bin2hex(ciphertext) << ") = " << bin2hex(m) << std::endl;
            return m;
        }
        ~unboxer() {
            memzero(k);
        }
    };
}

#endif
