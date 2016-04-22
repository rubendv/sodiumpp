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
#include <sodiumpp/z85.hpp>

std::string sodiumpp::crypto_auth(const std::string &m,const std::string &k)
{
    if (k.size() != crypto_auth_KEYBYTES) throw std::invalid_argument("incorrect key length");
    unsigned char a[crypto_auth_BYTES];
    ::crypto_auth(a,(const unsigned char *) m.c_str(),m.size(),(const unsigned char *) k.c_str());
    return std::string((char *) a,crypto_auth_BYTES);
}

void sodiumpp::crypto_auth_verify(const std::string &a,const std::string &m,const std::string &k)
{
    if (k.size() != crypto_auth_KEYBYTES) throw std::invalid_argument("incorrect key length");
    if (a.size() != crypto_auth_BYTES) throw std::invalid_argument("incorrect authenticator length");
    if (::crypto_auth_verify(
                           (const unsigned char *) a.c_str(),
                           (const unsigned char *) m.c_str(),m.size(),
                           (const unsigned char *) k.c_str()) == 0) return;
    throw sodiumpp::crypto_error("invalid authenticator");
}

std::string sodiumpp::crypto_box(const std::string &m,const std::string &n,const std::string &pk,const std::string &sk)
{
    if (pk.size() != crypto_box_PUBLICKEYBYTES) throw std::invalid_argument("incorrect public-key length");
    if (sk.size() != crypto_box_SECRETKEYBYTES) throw std::invalid_argument("incorrect secret-key length");
    if (n.size() != crypto_box_NONCEBYTES) throw std::invalid_argument("incorrect nonce length");
    size_t mlen = m.size() + crypto_box_ZEROBYTES;
    unsigned char mpad[mlen];
    for (size_t i = 0;i < crypto_box_ZEROBYTES;++i) mpad[i] = 0;
    for (size_t i = crypto_box_ZEROBYTES;i < mlen;++i) mpad[i] = m[i - crypto_box_ZEROBYTES];
    unsigned char cpad[mlen];
    ::crypto_box(cpad,mpad,mlen,
               (const unsigned char *) n.c_str(),
               (const unsigned char *) pk.c_str(),
               (const unsigned char *) sk.c_str()
               );
    return std::string(
                  (char *) cpad + crypto_box_BOXZEROBYTES,
                  mlen - crypto_box_BOXZEROBYTES
                  );
}

std::string sodiumpp::crypto_box_keypair(std::string& sk_string)
{
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    sk_string.resize(crypto_box_SECRETKEYBYTES, 0);
    ::crypto_box_keypair(pk,(unsigned char *)&sk_string[0]);
    return std::string((char *) pk,sizeof pk);
}

std::string sodiumpp::crypto_box_beforenm(const std::string &pk, const std::string &sk) {
    if (pk.size() != crypto_box_PUBLICKEYBYTES) throw std::invalid_argument("incorrect public-key length");
    if (sk.size() != crypto_box_SECRETKEYBYTES) throw std::invalid_argument("incorrect secret-key length");
    std::string k(crypto_box_BEFORENMBYTES, 0);
    ::crypto_box_beforenm((unsigned char *)&k[0], (const unsigned char *)&pk[0], (const unsigned char *)&sk[0]);
    return k;
}

std::string sodiumpp::crypto_box_afternm(const std::string &m,const std::string &n,const std::string &k) {
    if (k.size() != crypto_box_BEFORENMBYTES) throw std::invalid_argument("incorrect nm-key length");
    if (n.size() != crypto_box_NONCEBYTES) throw std::invalid_argument("incorrect nonce length");
    size_t mlen = m.size() + crypto_box_ZEROBYTES;
    unsigned char mpad[mlen];
    for (size_t i = 0;i < crypto_box_ZEROBYTES;++i) mpad[i] = 0;
    for (size_t i = crypto_box_ZEROBYTES;i < mlen;++i) mpad[i] = m[i - crypto_box_ZEROBYTES];
    unsigned char cpad[mlen];
    ::crypto_box_afternm(cpad,mpad,mlen,
                 (const unsigned char *) n.c_str(),
                 (const unsigned char *) k.c_str()
                 );
    return std::string(
                  (char *) cpad + crypto_box_BOXZEROBYTES,
                  mlen - crypto_box_BOXZEROBYTES
                  );
}

std::string sodiumpp::crypto_box_open_afternm(const std::string &c,const std::string &n,const std::string &k)
{
    if (k.size() != crypto_box_BEFORENMBYTES) throw std::invalid_argument("incorrect nm-key length");
    if (n.size() != crypto_box_NONCEBYTES) throw std::invalid_argument("incorrect nonce length");
    size_t clen = c.size() + crypto_box_BOXZEROBYTES;
    unsigned char cpad[clen];
    for (size_t i = 0;i < crypto_box_BOXZEROBYTES;++i) cpad[i] = 0;
    for (size_t i = crypto_box_BOXZEROBYTES;i < clen;++i) cpad[i] = c[i - crypto_box_BOXZEROBYTES];
    unsigned char mpad[clen];
    if (::crypto_box_open_afternm(mpad,cpad,clen,
                                  (const unsigned char *) n.c_str(),
                                  (const unsigned char *) k.c_str()
                                  ) != 0)
        throw sodiumpp::crypto_error("ciphertext fails verification");
    if (clen < crypto_box_ZEROBYTES)
        throw sodiumpp::crypto_error("ciphertext too short"); // should have been caught by _open
    return std::string(
                  (char *) mpad + crypto_box_ZEROBYTES,
                  clen - crypto_box_ZEROBYTES
                  );
}

std::string sodiumpp::crypto_box_open(const std::string &c,const std::string &n,const std::string &pk,const std::string &sk)
{
    if (pk.size() != crypto_box_PUBLICKEYBYTES) throw std::invalid_argument("incorrect public-key length");
    if (sk.size() != crypto_box_SECRETKEYBYTES) throw std::invalid_argument("incorrect secret-key length");
    if (n.size() != crypto_box_NONCEBYTES) throw std::invalid_argument("incorrect nonce length");
    size_t clen = c.size() + crypto_box_BOXZEROBYTES;
    unsigned char cpad[clen];
    for (size_t i = 0;i < crypto_box_BOXZEROBYTES;++i) cpad[i] = 0;
    for (size_t i = crypto_box_BOXZEROBYTES;i < clen;++i) cpad[i] = c[i - crypto_box_BOXZEROBYTES];
    unsigned char mpad[clen];
    if (::crypto_box_open(mpad,cpad,clen,
                        (const unsigned char *) n.c_str(),
                        (const unsigned char *) pk.c_str(),
                        (const unsigned char *) sk.c_str()
                        ) != 0)
        throw sodiumpp::crypto_error("ciphertext fails verification");
    if (clen < crypto_box_ZEROBYTES)
        throw sodiumpp::crypto_error("ciphertext too short"); // should have been caught by _open
    return std::string(
                  (char *) mpad + crypto_box_ZEROBYTES,
                  clen - crypto_box_ZEROBYTES
                  );
}

std::string sodiumpp::crypto_hash(const std::string &m)
{
    unsigned char h[crypto_hash_BYTES];
    ::crypto_hash(h,(const unsigned char *) m.c_str(),m.size());
    return std::string((char *) h,sizeof h);
}

std::string sodiumpp::crypto_onetimeauth(const std::string &m,const std::string &k)
{
    if (k.size() != crypto_onetimeauth_KEYBYTES) throw std::invalid_argument("incorrect key length");
    unsigned char a[crypto_onetimeauth_BYTES];
    ::crypto_onetimeauth(a,(const unsigned char *) m.c_str(),m.size(),(const unsigned char *) k.c_str());
    return std::string((char *) a,crypto_onetimeauth_BYTES);
}

void sodiumpp::crypto_onetimeauth_verify(const std::string &a,const std::string &m,const std::string &k)
{
    if (k.size() != crypto_onetimeauth_KEYBYTES) throw std::invalid_argument("incorrect key length");
    if (a.size() != crypto_onetimeauth_BYTES) throw std::invalid_argument("incorrect authenticator length");
    if (::crypto_onetimeauth_verify(
                                  (const unsigned char *) a.c_str(),
                                  (const unsigned char *) m.c_str(),m.size(),
                                  (const unsigned char *) k.c_str()) == 0) return;
    throw sodiumpp::crypto_error("invalid authenticator");
}

std::string sodiumpp::crypto_scalarmult_base(const std::string &n)
{
    unsigned char q[crypto_scalarmult_BYTES];
    if (n.size() != crypto_scalarmult_SCALARBYTES) throw std::invalid_argument("incorrect scalar length");
    ::crypto_scalarmult_base(q,(const unsigned char *) n.c_str());
    return std::string((char *) q,sizeof q);
}

std::string sodiumpp::crypto_scalarmult(const std::string &n,const std::string &p)
{
    unsigned char q[crypto_scalarmult_BYTES];
    if (n.size() != crypto_scalarmult_SCALARBYTES) throw std::invalid_argument("incorrect scalar length");
    if (p.size() != crypto_scalarmult_BYTES) throw std::invalid_argument("incorrect element length");
    ::crypto_scalarmult(q,(const unsigned char *) n.c_str(),(const unsigned char *) p.c_str());
    return std::string((char *) q,sizeof q);
}

std::string sodiumpp::crypto_secretbox(const std::string &m,const std::string &n,const std::string &k)
{
    if (k.size() != crypto_secretbox_KEYBYTES) throw std::invalid_argument("incorrect key length");
    if (n.size() != crypto_secretbox_NONCEBYTES) throw std::invalid_argument("incorrect nonce length");
    size_t mlen = m.size() + crypto_secretbox_ZEROBYTES;
    unsigned char mpad[mlen];
    for (size_t i = 0;i < crypto_secretbox_ZEROBYTES;++i) mpad[i] = 0;
    for (size_t i = crypto_secretbox_ZEROBYTES;i < mlen;++i) mpad[i] = m[i - crypto_secretbox_ZEROBYTES];
    unsigned char cpad[mlen];
    ::crypto_secretbox(cpad,mpad,mlen,(const unsigned char *) n.c_str(),(const unsigned char *) k.c_str());
    return std::string(
                  (char *) cpad + crypto_secretbox_BOXZEROBYTES,
                  mlen - crypto_secretbox_BOXZEROBYTES
                  );
}

std::string sodiumpp::crypto_secretbox_open(const std::string &c,const std::string &n,const std::string &k)
{
    if (k.size() != crypto_secretbox_KEYBYTES) throw std::invalid_argument("incorrect key length");
    if (n.size() != crypto_secretbox_NONCEBYTES) throw std::invalid_argument("incorrect nonce length");
    size_t clen = c.size() + crypto_secretbox_BOXZEROBYTES;
    unsigned char cpad[clen];
    for (size_t i = 0;i < crypto_secretbox_BOXZEROBYTES;++i) cpad[i] = 0;
    for (size_t i = crypto_secretbox_BOXZEROBYTES;i < clen;++i) cpad[i] = c[i - crypto_secretbox_BOXZEROBYTES];
    unsigned char mpad[clen];
    if (::crypto_secretbox_open(mpad,cpad,clen,(const unsigned char *) n.c_str(),(const unsigned char *) k.c_str()) != 0)
        throw sodiumpp::crypto_error("ciphertext fails verification");
    if (clen < crypto_secretbox_ZEROBYTES)
        throw sodiumpp::crypto_error("ciphertext too short"); // should have been caught by _open
    return std::string(
                  (char *) mpad + crypto_secretbox_ZEROBYTES,
                  clen - crypto_secretbox_ZEROBYTES
                  );
}

std::string sodiumpp::crypto_sign_keypair(std::string &sk_string)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    sk_string.resize(crypto_sign_SECRETKEYBYTES, 0);
    ::crypto_sign_keypair(pk,(unsigned char *)&sk_string[0]);
    return std::string((char *) pk,sizeof pk);
}

std::string sodiumpp::crypto_sign_open(const std::string &sm_string, const std::string &pk_string)
{
    if (pk_string.size() != crypto_sign_PUBLICKEYBYTES) throw std::invalid_argument("incorrect public-key length");
    size_t smlen = sm_string.size();
    unsigned char m[smlen];
    unsigned long long mlen;
    for (size_t i = 0;i < smlen;++i) m[i] = sm_string[i];
    if (::crypto_sign_open(
                         m,
                         &mlen,
                         m,
                         smlen,
                         (const unsigned char *) pk_string.c_str()
                         ) != 0)
        throw sodiumpp::crypto_error("ciphertext fails verification");
    return std::string(
                  (char *) m,
                  mlen
                  );
}

std::string sodiumpp::crypto_sign(const std::string &m_string, const std::string &sk_string)
{
    if (sk_string.size() != crypto_sign_SECRETKEYBYTES) throw std::invalid_argument("incorrect secret-key length");
    size_t mlen = m_string.size();
    unsigned char m[mlen+crypto_sign_BYTES];
    unsigned long long smlen;
    for (size_t i = 0;i < mlen;++i) m[i] = m_string[i];
    ::crypto_sign(
                m,
                &smlen,
                m,
                mlen,
                (const unsigned char *) sk_string.c_str()
                );
    return std::string(
                  (char *) m,
                  smlen
                  );
}

std::string sodiumpp::crypto_stream(size_t clen,const std::string &n,const std::string &k)
{
    if (n.size() != crypto_stream_NONCEBYTES) throw std::invalid_argument("incorrect nonce length");
    if (k.size() != crypto_stream_KEYBYTES) throw std::invalid_argument("incorrect key length");
    unsigned char c[clen];
    ::crypto_stream(c,clen,(const unsigned char *) n.c_str(),(const unsigned char *) k.c_str());
    return std::string((char *) c,clen);
}

std::string sodiumpp::crypto_stream_xor(const std::string &m,const std::string &n,const std::string &k)
{
    if (n.size() != crypto_stream_NONCEBYTES) throw std::invalid_argument("incorrect nonce length");
    if (k.size() != crypto_stream_KEYBYTES) throw std::invalid_argument("incorrect key length");
    size_t mlen = m.size();
    unsigned char c[mlen];
    ::crypto_stream_xor(c,
                      (const unsigned char *) m.c_str(),mlen,
                      (const unsigned char *) n.c_str(),
                      (const unsigned char *) k.c_str()
                      );
    return std::string((char *) c,mlen);
}

std::string sodiumpp::bin2hex(const std::string& bytes) {
    std::string hex(bytes.size()*2, 0);
    sodium_bin2hex(&hex[0], hex.size(), reinterpret_cast<const unsigned char *>(&bytes[0]), bytes.size());
    return hex;
}

std::string sodiumpp::hex2bin(const std::string& bytes) {
    if(bytes.size() % 2 != 0) throw std::invalid_argument("length must be even");
    std::string bin(bytes.size()/2, 0);
    size_t binlen;
    sodium_hex2bin((unsigned char *)&bin[0], bin.size(), &bytes[0], bytes.size(), nullptr, &binlen, nullptr);
    if(binlen != bin.size()) throw std::invalid_argument("string must be all hexadecimal digits");
    return bin;
}

void sodiumpp::memzero(std::string& bytes) {
    sodium_memzero((unsigned char *)&bytes[0], bytes.size());
}

void sodiumpp::mlock(std::string& bytes) {
    sodium_mlock((unsigned char *)&bytes[0], bytes.size());
}

void sodiumpp::munlock(std::string& bytes) {
    sodium_munlock((unsigned char *)&bytes[0], bytes.size());
}

std::string sodiumpp::crypto_shorthash(const std::string& m, const std::string& k) {
    if(k.size() != crypto_shorthash_KEYBYTES) throw std::invalid_argument("incorrect key length");
    std::string out(crypto_shorthash_BYTES, 0);
    ::crypto_shorthash((unsigned char *)&out[0], (const unsigned char *)&m[0], m.size(), (const unsigned char *)&k[0]);
    return out;
}

std::string sodiumpp::randombytes(size_t size) {
    std::string buf(size, 0);
    randombytes_buf(&buf[0], size);
    return buf;
}

std::string sodiumpp::encode_from_binary(const std::string& binary_bytes, sodiumpp::encoding enc) {
    switch(enc) {
        case encoding::binary:
            return binary_bytes;
        case encoding::hex:
            return bin2hex(binary_bytes);
        case encoding::z85:
            return z85::encode_with_padding(binary_bytes);
    }
}

std::string sodiumpp::decode_to_binary(const std::string& encoded_bytes, sodiumpp::encoding enc) {
    switch(enc) {
        case encoding::binary:
            return encoded_bytes;
        case encoding::hex:
            return hex2bin(encoded_bytes);
        case encoding::z85:
            return z85::decode_with_padding(encoded_bytes);
    }
}
