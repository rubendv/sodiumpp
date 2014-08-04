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
#include <sodiumpp/z85.hpp>

namespace sodiumpp {
    std::string crypto_auth(const std::string &m,const std::string &k);
    void crypto_auth_verify(const std::string &a,const std::string &m,const std::string &k);
    std::string crypto_box(const std::string &m,const std::string &n,const std::string &pk,const std::string &sk);
    std::string crypto_box_keypair(std::string &sk_string);
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
    std::string crypto_sign_keypair(std::string &sk_string);
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
        binary, hex, z85
    };
    
    std::string encode_from_binary(const std::string& binary_bytes, encoding encoding);
    std::string decode_to_binary(const std::string& encoded_bytes, encoding encoding);
    
    class encoded_bytes {
    public:
        encoding encoding;
        std::string bytes;
        encoded_bytes(const std::string& bytes, enum encoding encoding) : bytes(bytes), encoding(encoding) {}
        std::string to_binary() const { return decode_to_binary(bytes, encoding); }
        encoded_bytes to(enum encoding new_encoding) {
            return encoded_bytes(encode_from_binary(to_binary(), new_encoding), new_encoding);
        }
    };
    
    enum class purpose {
        box, sign
    };
    
    template <purpose P>
    struct key_lengths {
        size_t public_key;
        size_t secret_key;
    };
    
    template <>
    struct key_lengths<purpose::box> {
        size_t public_key = crypto_box_PUBLICKEYBYTES;
        size_t secret_key = crypto_box_SECRETKEYBYTES;
    };
    
    template <>
    struct key_lengths<purpose::sign> {
        size_t public_key = crypto_sign_PUBLICKEYBYTES;
        size_t secret_key = crypto_sign_SECRETKEYBYTES;
    };
    
    template <purpose P> class secret_key;
    
    template <purpose P>
    class public_key {
    private:
        public_key() {}
        std::string bytes;
    public:
        const purpose purpose = P;
        public_key(const encoded_bytes& bytes) : bytes(bytes.to_binary()) {}
        encoded_bytes get(encoding encoding=encoding::binary) const { return encoded_bytes(encode_from_binary(bytes, encoding), encoding); }
        const std::string& get_raw() const { return bytes; }
        friend class secret_key<P>;
    };
    
    template <sodiumpp::purpose P>
    std::ostream& operator<<(std::ostream& stream, const sodiumpp::public_key<P>& pk) {
        return stream << "public_key(\"" << pk.get(encoding::z85).bytes << "\")";
    }
    
    template <purpose P>
    class secret_key {
        std::string secret_bytes;
    public:
        const purpose purpose = P;
        public_key<P> pk;
        secret_key(const public_key<P>& pk, const encoded_bytes& secret_bytes) : pk(pk), secret_bytes(secret_bytes.to_binary()) {}
        secret_key(const secret_key<P>& other) : secret_bytes(other.secret_bytes), pk(other.pk) {}
        static_assert(P == purpose::box or P == purpose::sign, "purposes other than box and sign are not yet supported");
        secret_key() {
            if(P == purpose::box) {
                pk.bytes = crypto_box_keypair(secret_bytes);
            } else if(P == purpose::sign) {
                pk.bytes = crypto_sign_keypair(secret_bytes);
            } else {
                // Should be caught by the static_assert above
                std::invalid_argument("purposes other than box and sign are not yet supported");
            }
            sodium_mlock(&secret_bytes[0], secret_bytes.size());
        }
        encoded_bytes get(encoding encoding=encoding::binary) const { return encoded_bytes(encode_from_binary(secret_bytes, encoding), encoding); }
        ~secret_key() {
            memzero(secret_bytes);
        }
    };
    
    template <sodiumpp::purpose P>
    std::ostream& operator<<(std::ostream& stream, const sodiumpp::secret_key<P>& sk) {
        return stream << sk.pk << ", secret_key(\"" << sk.get(encoding::z85).bytes << "\")";
    }

    typedef public_key<purpose::box> box_public_key;
    typedef secret_key<purpose::box> box_secret_key;
    typedef public_key<purpose::sign> sign_public_key;
    typedef secret_key<purpose::sign> sign_secret_key;
    
    template <unsigned int sequentialbytes>
    class nonce {
    private:
        std::string bytes;
        bool overflow;
    public:
        static const unsigned int constantbytes = crypto_box_NONCEBYTES-sequentialbytes;
        static_assert(sequentialbytes <= crypto_box_NONCEBYTES and sequentialbytes > 0, "sequentialbytes can be at most crypto_box_NONCEBYTES and must be greater than 0");
        nonce() : nonce(""), overflow(false) {}
        nonce(const encoded_bytes& constant, bool uneven) : bytes(crypto_box_NONCEBYTES, 0), overflow(false) {
            std::string constant_decoded = constant.to_binary();
            if(constant_decoded.size() == 0) {
                randombytes_buf(&bytes[0], constantbytes);
            } else if(constant_decoded.size() != constantbytes) {
                throw std::invalid_argument("constant bytes does not have correct length");
            }
            
            std::copy(constant_decoded.begin(), constant_decoded.end(), &bytes[0]);
            
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
        encoded_bytes next(encoding encoding=encoding::binary) {
            increase();
            return get(encoding);
        }
        encoded_bytes get(encoding encoding=encoding::binary) const {
            if(overflow) {
                throw std::overflow_error("Sequential part of nonce has overflowed");
            } else {
                return encoded_bytes(encode_from_binary(bytes, encoding), encoding);
            }
        }
        encoded_bytes get_constant(encoding encoding=encoding::binary) const { return encoded_bytes(encode_from_binary(bytes.substr(0, constantbytes), encoding), encoding); }
        encoded_bytes get_sequential(encoding encoding=encoding::binary) const { return encoded_bytes(encode_from_binary(bytes.substr(constantbytes, sequentialbytes), encoding), encoding); }
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
    public:
        boxer(const box_public_key& pk, const box_secret_key& sk) : boxer(pk, sk, encoded_bytes("", encoding::binary)) {}
        boxer(const box_public_key& pk, const box_secret_key& sk, const encoded_bytes& nonce_constant) : k(crypto_box_beforenm(pk.get().to_binary(), sk.get().to_binary())), n(nonce_constant, sk.pk.get().to_binary() > pk.get().to_binary()) {
            sodium_mlock(&k[0], k.size());
        }
        noncetype get_nonce() const { return n; }
        encoded_bytes get_nonce_constant(encoding encoding=encoding::binary) const { return n.get_constant(encoding); }
        encoded_bytes box(std::string message, encoding encoding=encoding::binary) {
            std::string c = crypto_box_afternm(message, n.next().to_binary(), k);
            return encoded_bytes(encode_from_binary(c, encoding), encoding);
        }
        ~boxer() {
            memzero(k);
            sodium_munlock(&k[0], k.size());
        }
    };
    
    template <typename noncetype>
    class unboxer {
    private:
        noncetype n;
        std::string k;
    public:
        unboxer(const box_public_key& pk, const box_secret_key& sk, const encoded_bytes& nonce_constant) : k(crypto_box_beforenm(pk.get().to_binary(), sk.get().to_binary())), n(nonce_constant, pk.get().to_binary() > sk.pk.get().to_binary()) {
            sodium_mlock(&k[0], k.size());
        }
        noncetype get_nonce() const { return n; }
        encoded_bytes get_nonce_constant(encoding encoding=encoding::binary) const { return n.get_constant(encoding); }
        std::string unbox(const encoded_bytes& ciphertext) {
            std::string m = crypto_box_open_afternm(ciphertext.to_binary(), n.next().to_binary(), k);
            return m;
        }
        std::string unbox(const encoded_bytes& ciphertext, const encoded_bytes& sequentialpart) const {
            std::string m = crypto_box_open_afternm(ciphertext.to_binary(), n.get_constant().to_binary() + sequentialpart.to_binary(), k);
            return m;
        }
        ~unboxer() {
            memzero(k);
            sodium_munlock(&k[0], k.size());
        }
    };
}

#endif
