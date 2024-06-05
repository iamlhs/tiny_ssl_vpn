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
// rsa_b和rsa_pa：预先定义的大整数，分别代表RSA算法中的公钥指数和模数。
const mpz_class rsa_b(114514);//公钥指数
const mpz_class rsa_p(19260817);//公钥模数

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
    mpz_class h;//大数存储结果
    // h = (x^ rsa_b) mod rsa_p
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
    //char(8bit)*32安全密钥256位，nouce(Number once)随机数64位
    Chacha20Block(const char key[32], const char nonce[8]){
        const char *magic_constant = "expand 32-byte k";//字符串在Chacha20算法中是一个固定值，用于初始化密钥扩展。
        state[ 0] = pack4(magic_constant + 0*4);//这四行将magic_constant字符串的前16字节（4个4字节的部分）包装（pack）到state数组的第一个到第四个元素中。
        state[ 1] = pack4(magic_constant + 1*4);//pack4函数用于将4字节的数据打包成某个格式
        state[ 2] = pack4(magic_constant + 2*4);
        state[ 3] = pack4(magic_constant + 3*4);
        state[ 4] = pack4(key + 0*4);//接下来四行将密钥的前16字节包装到state数组的第五到第八个元素中。
        state[ 5] = pack4(key + 1*4);
        state[ 6] = pack4(key + 2*4);
        state[ 7] = pack4(key + 3*4);
        state[ 8] = pack4(key + 4*4);
        state[ 9] = pack4(key + 5*4);
        state[10] = pack4(key + 6*4);
        state[11] = pack4(key + 7*4);
        // 64 bit counter initialized to zero by default.
        //state[12]和state[13]被初始化为0，这通常用于作为一个64位的计数器。
        state[12] = 0;
        state[13] = 0;
        //接下来的两行将nonce的前8字节包装到state数组的第十四个和第十五个元素中。
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
         // 此函数生成Chacha20算法的一个轮次(quarter round)的结果。
        // 结果存储在result数组中，这个数组将会被用于生成下一个密钥流块。
        for (int i = 0; i < 16; i++) result[i] = state[i];
    // 定义一个宏，用于执行四分之一轮加密操作。
    // 它会对状态数组的四个元素进行轮混合操作，
    // 这些操作包括旋转和异或操作，以增强算法的混乱性和扩散性。
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
        // 将状态数组的当前值与结果数组的值相加，
        // 这样就结合了之前的密钥流和新的密钥流，增强了随机性。
        for (int i = 0; i < 16; i++) result[i] += state[i];
        // 获取状态数组中的计数器值
        uint32_t *counter = state + 12;
        counter[0]++;//计数器+1
        if (0 == counter[0]){// 如果计数器值归零，说明已经到达64字节块的界限，
            // 需要增加更高的32位计数器
            // wrap around occured, increment higher 32 bits of counter
            counter[1]++;
            // Limited to 2^64 blocks of 64 bytes each.
            // If you want to process more than 1180591620717411303424 bytes
            // you have other problems.
            // We could keep counting with counter[2] and counter[3] (nonce),
            // but then we risk reusing the nonce which is very bad.
            // 限制为2^64个64字节的块。
            // 如果你需要处理超过1180591620717411303424字节的数据，
            // 你会有其他问题要解决。
            // 我们可以选择继续使用counter[2]和counter[3]（nonce）计数，
            // 但是这样可能会复用nonce，这是非常危险的。
            assert(0 != counter[1]);
        }
    }
    // 这个函数将next函数生成的32位结果转换为8位，
    // 并存储在result8数组中，这个数组将会被用作加密的密钥流。
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
/*
Chacha20结构体的功能。
它说明了这个结构体用于将明文/加密的字节与Chacha20Block生成的数据进行异或操作。
加密和解密是相同的操作，可以通过跳过Chacha20Block来并行处理。
如果密钥被重复使用，消息可以被解密。
同时，已知加密文本和位置可以被篡改，这可能是一个安全漏洞。
*/
    Chacha20Block block;//一个Chacha20Block对象，用于生成密钥流。
    uint8_t keystream8[64];//一个长度为64的字节数组，用于存储生成的密钥流
    size_t position;//一个大小为size_t的变量，用于记录当前处理到的密钥流位置
    Chacha20(//在enctun.run()用到
        const char key[32],
        const char nonce[8],
        uint64_t counter = 0//一个可选的64位计数器（默认为0）
    ): block(key, nonce), position(64){
        block.set_counter(counter);
    }
    //对字节数组bytes进行加密（或解密，因为加密和解密在Chacha20中是相同的操作）
    void crypt(uint8_t *bytes, size_t n_bytes){
        for (size_t i = 0; i < n_bytes; i++){//循环每个字节
            if (position >= 64){//已达bytes末尾
                block.next(keystream8);//调用block.next函数生成新的密钥流
                position = 0;//开始处理下一个字节
            }
            bytes[i] ^= keystream8[position];//将keystream8数组中的每个字节与bytes数组中的对应字节进行异或操作
            position++;//位置+1
        }
    }
};

#endif

