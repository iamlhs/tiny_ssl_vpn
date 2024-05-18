#ifndef CRYPTO_HPP
#define CRYPTO_HPP
#include <gmpxx.h>
#include <cstdint>
#include "message.pb.h"

/*RSA：非对称加密算法，使用两个大质数的乘积作为模数n，一个质数作为公钥指数e，以及私钥指数d*/

const int buffer_size = 1024;
const int max_prime_bits = 512;
const int nonce_bits = 8;
const int key_bits = 32;

const mpz_class rsa_b(114514);
const mpz_class rsa_p(19260817);

//m（明文消息），e（公钥指数），和n（模数），对m进行加密
mpz_class rsa_encrypt(mpz_class m, mpz_class e, mpz_class n) {
    mpz_class c;
    //计算c=m^e mod n，得到密文c并返回
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
    return c;
}

mpz_class rsa_decrypt(mpz_class c, mpz_class d, mpz_class n) {
    mpz_class m;
    mpz_powm(m.get_mpz_t(), c.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
    return m;
}

mpz_class get_hash(mpz_class x) { 
    mpz_class h;
    mpz_powm(h.get_mpz_t(), x.get_mpz_t(), rsa_b.get_mpz_t(), rsa_p.get_mpz_t());
    return h;
}

mpz_class gen_prime_key(mpz_class c_rnd, mpz_class s_rnd, mpz_class p_rnd) { // something like HMAC-SHA256
    mpz_class p_key;
    mpz_class h = get_hash(c_rnd + s_rnd);
    p_key = h * p_rnd  % (mpz_class(1) << max_prime_bits);
    return p_key;
}

struct Chacha20Block {
    // This is basically a random number generator seeded with key and nonce.
    // Generates 64 random bytes every time count is incremented.

    uint32_t state[16];

    static uint32_t rotl32(uint32_t x, int n){
        return (x << n) | (x >> (32 - n));
    }

    static uint32_t pack4(const char *a){
        return
            uint32_t(a[0] << 0*8) |
            uint32_t(a[1] << 1*8) |
            uint32_t(a[2] << 2*8) |
            uint32_t(a[3] << 3*8);
    }

    static void unpack4(uint32_t src, uint8_t *dst){
        dst[0] = (src >> 0*8) & 0xff;
        dst[1] = (src >> 1*8) & 0xff;
        dst[2] = (src >> 2*8) & 0xff;
        dst[3] = (src >> 3*8) & 0xff;
    }

    Chacha20Block(const char key[32], const char nonce[8]){
        const char *magic_constant = "expand 32-byte k";
        state[ 0] = pack4(magic_constant + 0*4);
        state[ 1] = pack4(magic_constant + 1*4);
        state[ 2] = pack4(magic_constant + 2*4);
        state[ 3] = pack4(magic_constant + 3*4);
        state[ 4] = pack4(key + 0*4);
        state[ 5] = pack4(key + 1*4);
        state[ 6] = pack4(key + 2*4);
        state[ 7] = pack4(key + 3*4);
        state[ 8] = pack4(key + 4*4);
        state[ 9] = pack4(key + 5*4);
        state[10] = pack4(key + 6*4);
        state[11] = pack4(key + 7*4);
        // 64 bit counter initialized to zero by default.
        state[12] = 0;
        state[13] = 0;
        state[14] = pack4(nonce + 0*4);
        state[15] = pack4(nonce + 1*4);
    }

    void set_counter(uint64_t counter){
        // Want to process many blocks in parallel?
        // No problem! Just set the counter to the block you want to process.
        state[12] = uint32_t(counter);
        state[13] = counter >> 32;
    }

    void next(uint32_t result[16]){
        // This is where the crazy voodoo magic happens.
        // Mix the bytes a lot and hope that nobody finds out how to undo it.
        for (int i = 0; i < 16; i++) result[i] = state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

        for (int i = 0; i < 10; i++){
            CHACHA20_QUARTERROUND(result, 0, 4, 8, 12)
            CHACHA20_QUARTERROUND(result, 1, 5, 9, 13)
            CHACHA20_QUARTERROUND(result, 2, 6, 10, 14)
            CHACHA20_QUARTERROUND(result, 3, 7, 11, 15)
            CHACHA20_QUARTERROUND(result, 0, 5, 10, 15)
            CHACHA20_QUARTERROUND(result, 1, 6, 11, 12)
            CHACHA20_QUARTERROUND(result, 2, 7, 8, 13)
            CHACHA20_QUARTERROUND(result, 3, 4, 9, 14)
        }

        for (int i = 0; i < 16; i++) result[i] += state[i];

        uint32_t *counter = state + 12;
        // increment counter
        counter[0]++;
        if (0 == counter[0]){
            // wrap around occured, increment higher 32 bits of counter
            counter[1]++;
            // Limited to 2^64 blocks of 64 bytes each.
            // If you want to process more than 1180591620717411303424 bytes
            // you have other problems.
            // We could keep counting with counter[2] and counter[3] (nonce),
            // but then we risk reusing the nonce which is very bad.
            assert(0 != counter[1]);
        }
    }
    
    void next(uint8_t result8[64]){
        uint32_t temp32[16];
        
        next(temp32);
        
        for (size_t i = 0; i < 16; i++) unpack4(temp32[i], result8 + i*4);
    }
};

struct Chacha20 {
    // XORs plaintext/encrypted bytes with whatever Chacha20Block generates.
    // Encryption and decryption are the same operation.
    // Chacha20Blocks can be skipped, so this can be done in parallel.
    // If keys are reused, messages can be decrypted.
    // Known encrypted text with known position can be tampered with.
    // See https://en.wikipedia.org/wiki/Stream_cipher_attack

    Chacha20Block block;
    uint8_t keystream8[64];
    size_t position;

    Chacha20(
        const char key[32],
        const char nonce[8],
        uint64_t counter = 0
    ): block(key, nonce), position(64){
        block.set_counter(counter);
    }

    void crypt(uint8_t *bytes, size_t n_bytes){
        for (size_t i = 0; i < n_bytes; i++){
            if (position >= 64){
                block.next(keystream8);
                position = 0;
            }
            bytes[i] ^= keystream8[position];
            position++;
        }
    }
};

#endif