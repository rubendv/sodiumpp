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
#include <string>
#include <stdexcept>

extern "C" {
#include <sodium.h>
}
#include <sodiumpp/z85.hpp>

namespace sodiumpp {
    std::string crypto_auth(const std::string &m,const std::string &k);
    void crypto_auth_verify(const std::string &a,const std::string &m,const std::string &k);
    /**
     * Performs the box operation on message m, using nonce n, from secret key sk to public key pk.
     * Throws std::invalid_argument if any of the arguments are invalid
     */
    std::string crypto_box(const std::string &m,const std::string &n,const std::string &pk,const std::string &sk);
    /**
     * Generate a new keypair for box operations.
     * The secret key is stored in sk_string, and the public key is returned.
     * Throws std::invalid_argument if any of the arguments are invalid.
     * This function was changed from the official NaCl API: it accepts a reference instead of a pointer to sk_string.
     */
    std::string crypto_box_keypair(std::string &sk_string);
    /**
     * If many box operations are performed between the same pair of keypairs,
     * The operation can be split in crypto_box_beforenm, which is performed once and crypto_box_afternm, 
     * which is performed for every message, in order to increase performance.
     * This function takes a receiver public key pk and a sender secret key sk, and returns the k parameter that should be used in afternm.
     * Throws std::invalid_argument if any of the arguments are invalid.
     */
    std::string crypto_box_beforenm(const std::string &pk, const std::string &sk);
    /**
     * If many box operations are performed between the same pair of keypairs,
     * The operation can be split in beforenm, which is performed once and afternm, 
     * which is performed for every message, in order to increase performance.
     * This function takes a message m, a nonce n and the parameter k which can be obtained from crypto_box_beforenm.
     * Throws std::invalid_argument if any of the arguments are invalid.
     */
    std::string crypto_box_afternm(const std::string &m,const std::string &n,const std::string &k);
    /**
     * Unbox a boxed message c, using the nonce n, with the sender's public key pk and the receiver's secret key sk.
     * Returns the unboxed message.
     * Throws crypto_error if the ciphertext failed verification, throws std::invalid_argument if any of the arguments are invalid.
     */
    std::string crypto_box_open(const std::string &c,const std::string &n,const std::string &pk,const std::string &sk);
    /**
     * If many unbox operations are performed between the same pair of keypairs,
     * The operation can be split in crypto_box_beforenm, which is performed once and crypto_box_open_afternm, 
     * which is performed for every message, in order to increase performance.
     * This function takes a receiver public key pk and a sender secret key sk, and returns the k parameter that should be used in afternm.
     * Throws crypto_error if the ciphertext fails verification, throws std::invalid_argument if any of the arguments are invalid.
     */
    std::string crypto_box_open_afternm(const std::string &c,const std::string &n,const std::string &k);
    std::string crypto_hash(const std::string &m);
    std::string crypto_onetimeauth(const std::string &m,const std::string &k);
    void crypto_onetimeauth_verify(const std::string &a,const std::string &m,const std::string &k);
    std::string crypto_scalarmult_base(const std::string &n);
    std::string crypto_scalarmult(const std::string &n,const std::string &p);
    std::string crypto_secretbox(const std::string &m,const std::string &n,const std::string &k);
    std::string crypto_secretbox_open(const std::string &c,const std::string &n,const std::string &k);
    /**
     * Generate a new keypair for sign operations.
     * This function was changed from the official NaCl API: it accepts a reference instead of a pointer to sk_string.
     */
    std::string crypto_sign_keypair(std::string &sk_string);
    std::string crypto_sign_open(const std::string &sm_string, const std::string &pk_string);
    std::string crypto_sign(const std::string &m_string, const std::string &sk_string);
    std::string crypto_stream(size_t clen,const std::string &n,const std::string &k);
    std::string crypto_stream_xor(const std::string &m,const std::string &n,const std::string &k);
    std::string crypto_shorthash(const std::string& m, const std::string& k);
    std::string randombytes(size_t size);
    
    /**
     * Encode the binary string bytes to a hexadecimally encoded string, 2 lowercase hexadecimal digits per byte.
     */
    std::string bin2hex(const std::string& bytes);
    /**
     * Decode the hexadecimally encoded string bytes to a binary string, 2 lowercase hexadecimal digits per byte.
     */
    std::string hex2bin(const std::string& bytes);
    
    /**
     * Securely erases the contents of the string bytes.
     */
    void memzero(std::string& bytes);
    /**
     * Locks the memory used by the string bytes in memory, preventing it from being swapped out.
     */
    void mlock(std::string& bytes);
    /**
     * Unlocks the memory used by the string bytes, allowing it to be swapped out again.
     */
    void munlock(std::string& bytes);
    
    /**
     * Exception class for cryptographic errors: failed verifications etc.
     */
    class crypto_error : public std::runtime_error {
    public:
        crypto_error(const std::string& what) : std::runtime_error(what) {}
    };
    
    /**
     * Encoding of a series of bytes.
     */
    enum class encoding {
        binary, /** No special encoding is applied, the bytes are kept as-is. */
        hex, /** The bytes are encoded with two lower case hexadecimal digits per byte. */
        z85 /** The bytes are encoded using Z85 encoding with padding if necessary. */
    };
    
    /**
     * Encode binary_bytes to a string of bytes in the specified encoding.
     */
    std::string encode_from_binary(const std::string& binary_bytes, encoding enc);
    /**
     * Decode encoded_bytes to a string of binary bytes, using the specified encoding.
     */
    std::string decode_to_binary(const std::string& encoded_bytes, encoding enc);
    

    /**
     * Holds a string of bytes in a certain encoding.
     */
    class encoded_bytes {
    public:
        std::string bytes; /** The encoded bytes */
        encoding enc; /** The encoding that was used */
        /**
         * Constructor from a string of bytes that is assumed to be encoded in the specified encoding. 
         */
        encoded_bytes(const std::string& bytes, enum encoding enc) : bytes(bytes), enc(enc) {}
        /**
         * Convenience method for quickly getting the binary string corresponding to the encoded bytes.
         */
        std::string to_binary() const { return decode_to_binary(bytes, enc); }
        /**
         * Return a new encoded_bytes object that contains the same data but encoded with new_encoding.
         */
        encoded_bytes to(enum encoding new_encoding) {
            return encoded_bytes(encode_from_binary(to_binary(), new_encoding), new_encoding);
        }
    };
    
    /**
     * The purpose of a cryptographic key.
     */
    enum class key_purpose {
        box, /** An NaCl box/unbox key */
        sign /** An NaCl sign/verify key */
    };
    
    /**
     * Holds the lengths of keys for the key_purpose P
     */
    template <key_purpose P>
    struct key_lengths {
        static const size_t public_key; /** The length in bytes of a public key for the key_purpose P */
        static const size_t secret_key; /** The length in bytes of a secret key for the key_purpose P */
    };
    
    template <>
    struct key_lengths<key_purpose::box> {
        static const size_t public_key = crypto_box_PUBLICKEYBYTES;
        static const size_t secret_key = crypto_box_SECRETKEYBYTES;
    };
    
    template <>
    struct key_lengths<key_purpose::sign> {
        static const size_t public_key = crypto_sign_PUBLICKEYBYTES;
        static const size_t secret_key = crypto_sign_SECRETKEYBYTES;
    };
    
    template <key_purpose P> class secret_key;
    
    /**
     * Manages a public key.
     *
     * The template parameter P is the key_purpose of this key: at the moment this is either key_purpose::box or purose::sign.
     */
    template <key_purpose P>
    class public_key {
    private:
        /**
         * Private default constructor to avoid inproperly constructed public_keys
         */
        public_key() {}
        std::string bytes; /** The binary encoded bytes of this key */
    public:
        const key_purpose purpose = P; /** The purpose of this key */
        /**
         * Construct a public_key from encoded bytes
         */
        public_key(const encoded_bytes& bytes) : bytes(bytes.to_binary()) {}
        /**
         * Get the encoding encoded bytes of this public_key
         */
        encoded_bytes get(encoding enc=encoding::binary) const { return encoded_bytes(encode_from_binary(bytes, enc), enc); }
        bool operator==(const public_key<P>& other) {
            return bytes == other.bytes;
        }
        friend class secret_key<P>;
    };
    
    template <sodiumpp::key_purpose P>
    std::ostream& operator<<(std::ostream& stream, const sodiumpp::public_key<P>& pk) {
        return stream << "public_key(\"" << pk.get(encoding::z85).bytes << "\")";
    }
    
    /**
     * Manages generation and safekeeping of a secret key.
     *
     * The template parameter P is the purpose of this key: at the moment this is either key_purpose::box or key_purpose::sign.
     * 
     * The memory region that contains the bytes of the secrey key is locked, 
     * which means it should not be allowed to be swapped to disk,
     * and the bytes are zeroed when the object is destroyed.
     */
    template <key_purpose P>
    class secret_key {
        std::string secret_bytes;
    public:
        const key_purpose purpose = P; /** The purpose of this key */
        public_key<P> pk; /**< The public key corresponding to this secret key */
        /**
         * Construct a secret key from a pregenerated public and secret key.
         */
        secret_key(const public_key<P>& pk, const encoded_bytes& secret_bytes) : pk(pk), secret_bytes(secret_bytes.to_binary()) {}
        /**
         * Copy constructor
         */
        secret_key(const secret_key<P>& other) : secret_bytes(other.secret_bytes), pk(other.pk) {}
        static_assert(P == key_purpose::box or P == key_purpose::sign, "purposes other than box and sign are not yet supported");
        /**
         * Default constructor: automatically generates new keypair.
         */
        secret_key() {
            if(P == key_purpose::box) {
                pk.bytes = crypto_box_keypair(secret_bytes);
            } else if(P == key_purpose::sign) {
                pk.bytes = crypto_sign_keypair(secret_bytes);
            } else {
                // Should be caught by the static_assert above
                std::invalid_argument("purposes other than box and sign are not yet supported");
            }
            mlock(secret_bytes);
        }
        /**
         * Get the encoded bytes of the secret key.
         */
        encoded_bytes get(encoding enc=encoding::binary) const { return encoded_bytes(encode_from_binary(secret_bytes, enc), enc); }
        /**
         * Securely erase and unlock the memory containing the secret key.
         */
        ~secret_key() {
            memzero(secret_bytes);
            munlock(secret_bytes);
        }
        bool operator==(const secret_key<P>& other) {
            return secret_bytes.size() == other.secret_bytes.size() and sodium_memcmp(&secret_bytes[0], &(other.secretbytes[0]), secret_bytes.size()) and pk == other.pk;
        }
    };
    
    template <sodiumpp::key_purpose P>
    std::ostream& operator<<(std::ostream& stream, const sodiumpp::secret_key<P>& sk) {
        return stream << sk.pk << ", secret_key(\"" << sk.get(encoding::z85).bytes << "\")";
    }

    /* Convenience typedefs */
    typedef public_key<key_purpose::box> box_public_key;
    typedef secret_key<key_purpose::box> box_secret_key;
    typedef public_key<key_purpose::sign> sign_public_key;
    typedef secret_key<key_purpose::sign> sign_secret_key;
    
    /**
     * Nonce type that consists of a constant part and a sequential part that can be incremented.
     *
     * The template parameter sequentialbytes specifies the number of bytes to allocate to the sequential part.
     * This value must be at least 1, and at most crypto_box_NONCEBYTES.
     *
     * Any remaining bytes (crypto_box_NONCEBYTES - sequentialbytes) are allocated to the constant part.
     */
    template <unsigned int sequentialbytes>
    class nonce {
    private:
        /** The current bytes of this nonce, it consists of the constant bytes followed by the sequential bytes in big-endian format. */
        std::string bytes;  
        /** Indicates an overflow of the sequential part of the nonce if true. */
        bool overflow; 
    public:
        /** The number of bytes allocated to the constant part */
        static const unsigned int constantbytes = crypto_box_NONCEBYTES-sequentialbytes; 
        static_assert(sequentialbytes <= crypto_box_NONCEBYTES and sequentialbytes > 0, "sequentialbytes can be at most crypto_box_NONCEBYTES and must be greater than 0");
        /**
         * Default constructor: initializes the constant and sequential parts to zeroes.
         */
        nonce() : nonce(encoded_bytes("", encoding::binary), false, false) {}
        /**
         * Construct a nonce from the encoded constant.
         * If the length of the constant is 0 and generate_constant is true (the default), the constant bytes will be initialized randomly, and if generated_constant is false they will be set to zero.
         * If the length of the constant is > 0, the length must be exactly constantbytes and will be used to initialize the constant part of the nonce.
         * Throws std::invalid_argument if constant does not have the correct length.
         * If uneven is true the sequential part of the generated nonces will always be uneven, otherwise the sequential part will always be even.
         */
        nonce(const encoded_bytes& constant, bool uneven, bool generate_constant=true) : bytes(crypto_box_NONCEBYTES, 0), overflow(false) {
            std::string constant_decoded = constant.to_binary();
            if(constant_decoded.size() == 0) {
                if(generate_constant) {
                    randombytes_buf(&bytes[0], constantbytes);
                }
            } else if(constant_decoded.size() != constantbytes) {
                throw std::invalid_argument("constant bytes does not have correct length");
            }
            
            std::copy(constant_decoded.begin(), constant_decoded.end(), &bytes[0]);
            
            if(uneven) {
                bytes[bytes.size()-1] = 1;
            }
        }
        /**
         * Construct from encoded constant and sequential parts.
         * Throws std::invalid_argument if constant and/or sequentialpart do not have the correct number of decoded bytes.
         */
        nonce(const encoded_bytes& constant, const encoded_bytes& sequentialpart) : overflow(false) {
            std::string constant_decoded = constant.to_binary();
            if(constant_decoded.size() != constantbytes) {
                throw std::invalid_argument("incorrect number of decoded bytes in constant");
            }
            std::string sequentialpart_decoded = sequentialpart.to_binary();
            if(sequentialpart_decoded.size() != sequentialbytes) {
                throw std::invalid_argument("incorrect number of decoded bytes in sequential part");
            }
            bytes = constant_decoded + sequentialpart_decoded;
        }
        /**
         * Construct from encoded nonce.
         * Throws std::invalid_argument if the number of decoded bytes is not crypto_box_NONCEBYTES.
         */
        nonce(const encoded_bytes& encoded) {
            std::string decoded = encoded.to_binary();
            if(decoded.size() != crypto_box_NONCEBYTES) {
                throw std::invalid_argument("incorrect number of decoded bytes");
            }
            bytes = decoded;
        }
        /**
         * Increment the sequential part of the nonce by 2.
         * This function does NOT throw an exception on overflow, but delays this until an attempt is made to read the sequential part.
         */
        void increment() {
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
        /**
         * Increments the sequential part of the nonce by 2 and returns the new value of the nonce in the specified encoding.
         * Throws std::overflow_error if an overflow occurred during this or a previous increment.
         */
        encoded_bytes next(encoding enc=encoding::binary) {
            increment();
            return get(enc);
        }
        /**
         * Returns the current value of the nonce in the specified encoding.
         * Throws std::overflow_error if an overflow occurred during a previous increment.
         */
        encoded_bytes get(encoding enc=encoding::binary) const {
            if(overflow) {
                throw std::overflow_error("Sequential part of nonce has overflowed");
            } else {
                return encoded_bytes(encode_from_binary(bytes, enc), enc);
            }
        }
        /**
         * Returns the value of the constant part of the nonce in the specified encoding.
         */
        encoded_bytes get_constant(encoding enc=encoding::binary) const { 
            return encoded_bytes(encode_from_binary(bytes.substr(0, constantbytes), enc), enc); 
        }
        /**
         * Returns the current value of the sequential part of the nonce in the specified encoding.
         * Throws std::overflow_error if an overflow occurred during a previous increment.
         */
        encoded_bytes get_sequential(encoding enc=encoding::binary) const { 
            return encoded_bytes(get(encoding::binary).bytes.substr(constantbytes, sequentialbytes), enc); 
        }
        bool operator==(const nonce<sequentialbytes>& other) {
            return bytes == other.bytes and overflow == other.overflow;
        }
    };

    /* Convenience typedefs */
    typedef nonce<8> nonce64;
    typedef nonce<4> nonce32;
    typedef nonce<2> nonce16;

    template <unsigned int sequentialbytes>
    std::ostream& operator<<(std::ostream& s, nonce<sequentialbytes> n) {
        s << bin2hex(n.constant()) << " - " << bin2hex(n.sequential());
        return s;
    }
    
    /**
     * Boxes a series of messages between sender's secret key and a receiver's public key using automatically generated nonces.
     * The sequential part of nonces is even if the sender's public key is lexicographically smaller than the receiver's public key, and uneven otherwise.
     * The constant part of nonces is randomly generated or supplied by the user.
     *
     * The template parameter noncetype specifies the type of nonce that should be used by the boxer.
     *
     * Splits the box operation into crypto_box_beforenm and crypto_box_afternm for increased performance.
     * The beforenm parameter is locked into memory for the lifetime of the boxer and securely erased at destroy time.
     */
    template <typename noncetype>
    class boxer {
    private:
        noncetype n;
        std::string k;
    public:
        /**
         * Construct from the receiver's public key pk and the sender's secret key sk
         */
        boxer(const box_public_key& pk, const box_secret_key& sk) : boxer(pk, sk, encoded_bytes("", encoding::binary)) {}
        /**
         * Construct from the receiver's public key pk, the sender's secret key sk and an encoded constant part for the nonces.
         */
        boxer(const box_public_key& pk, const box_secret_key& sk, const encoded_bytes& nonce_constant) : k(crypto_box_beforenm(pk.get().to_binary(), sk.get().to_binary())), n(nonce_constant, sk.pk.get().to_binary() > pk.get().to_binary()) {
            mlock(k);
        }
        /**
         * Returns the current nonce.
         */
        noncetype get_nonce() const { return n; }
        /**
         * Convenience method to get the constant part of the nonce.
         */
        encoded_bytes get_nonce_constant(encoding enc=encoding::binary) const { return n.get_constant(enc); }
        /**
         * Box the message m and return the boxed message in the specified encoding.
         * Automatically increments the nonce after each message.
         * The nonce that was used will be put in used_n.
         */
        encoded_bytes box(std::string message, noncetype& used_n, encoding enc=encoding::binary) {
            std::string c = crypto_box_afternm(message, n.get().to_binary(), k);
            used_n = n;
            n.increment();
            return encoded_bytes(encode_from_binary(c, enc), enc);
        }
        /**
         * Box the message m and return the boxed message in the specified encoding.
         * Automatically increments the nonce after each message.
         */
        encoded_bytes box(std::string message, encoding enc=encoding::binary) {
            noncetype current_n;
            return box(message, current_n, enc);
        }
        /**
         * Securely erase the crypto_box_afternm parameter,
         * and unlock the memory that contained it.
         */
        ~boxer() {
            memzero(k);
            munlock(k);
        }
    };
    
    /**
     * Unboxes a series of messages between sender's public key and a receiver's secret key using automatically generated nonces.
     * The sequential part of nonces is even if the sender's public key is lexicographically smaller than the receiver's public key, and uneven otherwise.
     * The constant part of nonces is supplied by the user.
     *
     * The template parameter noncetype specifies the type of nonce that should be used by the boxer.
     *
     * Splits the box operation into crypto_box_beforenm and crypto_box_open_afternm for increased performance.
     * The beforenm parameter is locked into memory for the lifetime of the unboxer and securely erased at destroy time.
     */
    template <typename noncetype>
    class unboxer {
    private:
        noncetype n;
        std::string k;
    public:
        /**
         * Construct from the sender's public key pk, the receiver's secret key sk and an encoded constant part for the nonces.
         */
        unboxer(const box_public_key& pk, const box_secret_key& sk, const encoded_bytes& nonce_constant) : k(crypto_box_beforenm(pk.get().to_binary(), sk.get().to_binary())), n(nonce_constant, pk.get().to_binary() > sk.pk.get().to_binary()) {
            mlock(k);
        }
        /**
         * Returns the current nonce.
         */
        noncetype get_nonce() const { return n; }
        /**
         * Convenience method to get the constant part of the nonce.
         */
        encoded_bytes get_nonce_constant(encoding encoding=encoding::binary) const { return n.get_constant(encoding); }
        /**
         * Unbox the encoded message m and return the unboxed message.
         * Automatically increments the nonce after each message.
         */
        std::string unbox(const encoded_bytes& ciphertext) {
            std::string m = crypto_box_open_afternm(ciphertext.to_binary(), n.get().to_binary(), k);
            n.increment();
            return m;
        }
        /**
         * Unbox the encoded message m and return the unboxed message.
         * Does NOT use or change the current nonce, but uses the nonce in n_override instead.
         */
        std::string unbox(const encoded_bytes& ciphertext, const noncetype& n_override) const {
            std::string m = crypto_box_open_afternm(ciphertext.to_binary(), n_override.get().to_binary(), k);
            return m;
        }
        /**
         * Securely erase the crypto_box_afternm parameter,
         * and unlock the memory that contained it.
         */
        ~unboxer() {
            memzero(k);
            munlock(k);
        }
    };
}

#endif
