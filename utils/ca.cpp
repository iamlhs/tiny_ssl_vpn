#include <spdlog/spdlog.h>
#include"./crypto.hpp"
#include "../utils/crypto.hpp"// 用于加密函数的utils目录中的文件。
#include <fstream> 
#include <fstream>
#include <string>
// 定义证书、CA证书和CA密钥的默认文件名。
const char default_cert_file[] = "server.pubkey";
const char default_ca_cert_file[] = "ca.pubkey";
const char default_ca_key_file[] = "ca.privkey";
// 为加密目的创建一个随机数生成器。
gmp_randclass rng(gmp_randinit_default);
// 声明大整数变量，用于RSA公钥组件。
mpz_class n, e, d;

int main(int argc, char *argv[]) {
// 检查命令行参数的数量。
    if (argc < 2 || argc > 4) {
    // 如果参数不符合预期，显示一个错误信息并返回1（错误代码）。
        spdlog::error("Usage: ca <cert_file> [ca_cert_file] [ca_key_file]");
        spdlog::error("  Default ca_cert_file = {}, ca_key_file = {}", default_ca_cert_file, default_ca_key_file);
        return 1;
    }
    //在编写代码以处理命令行参数时
    std::string cert_file = argv[1];
    // 获取证书文件和可选的CA证书和密钥文件
    //若存在第三个参数，则是CA证书文件
    //若存在第四个参数，则是私钥文件
    std::string ca_cert_file = argc > 2 ? argv[2] : default_ca_cert_file;
    std::string ca_key_file = argc > 3 ? argv[3] : default_ca_key_file;
    //打开证书文件，用于读取
    std::ifstream cert(cert_file);
    if (!cert) {
        spdlog::error("Cannot open cert_file {}", cert_file);
        return 1;
    }
    //创建大整数类型，从证书中读取公钥，cert_n:公钥的模数(modulus)，cert_e:公钥的指数
    mpz_class cert_n, cert_e;
    cert >> cert_n >> cert_e;
    cert.close();
    // 打印证书的前16个字符
    spdlog::info("Read certificate, n = {}, e = {}", cert_n.get_str(16), cert_e.get_str(16));
    // Check if the CA certificate and key files exist, if not, generate new keys.
    if (!std::ifstream(ca_cert_file) || !std::ifstream(ca_key_file)) {
        //打开新输出文件，用于新的证书和密钥
        std::ofstream ca_cert(ca_cert_file);
        std::ofstream ca_key(ca_key_file);
        /*
        这段代码首先检查是否存在 CA 证书和密钥文件。如果不存在，它将生成一个新的 RSA 密钥对，并将它们保存到指定的文件中。具体步骤如下：
        创建两个输出文件流，用于写入新的 CA 证书和密钥。
        生成两个大素数 p 和 q，然后计算 n（模数）为 p * q，以及 phi（欧拉函数）为 (p - 1) * (q - 1)。
        随机选择一个数 e，它满足 1 < e < phi 且 e 与 phi 的最大公约数为 1。这通常通过多次尝试和测试来完成。
        计算 d，它是 e 的模 phi 的逆元，即 d * e ≡ 1 (mod phi)。详情原理见ppt。
        将 n 和 e 写入 CA 证书文件，将 n 和 d 写入密钥文件。
        打印信息表明新的 RSA 密钥对已生成并保存到文件中。
        如果 CA 证书和密钥文件已经存在，程序将读取这些文件中的数据，而不是生成新的密钥对。
        */
       // 生成新的RSA密钥对组件。
        mpz_class p, q, inv, phi;
        mpz_class one = 1;
        mpz_class tmp_p = rng.get_z_bits(max_prime_bits);
        mpz_class tmp_q = rng.get_z_bits(max_prime_bits);
        mpz_nextprime(p.get_mpz_t(), tmp_p.get_mpz_t());
        mpz_nextprime(q.get_mpz_t(), tmp_q.get_mpz_t());
        n = p * q;
        phi = (p - one) * (q - one);
        // find a number e such that 1 < e < phi and gcd(e, phi) = 1
        mpz_class tmp;
        //根据ppt所述原理，在RSA算法中，e必须满足两个条件：
        //它必须是phi(n)（即(p-1)(q-1)，其中p和q是两个大质数）的一个原根，
        //这意味着存在一个整数d使得e * d ≡ 1 (mod phi(n))，并且它应该是一个相对较小的质数，以便于计算和验证。
        do {
            //使用随机数生成器rng从0~phi(即p*q-1, p、q为大质数)获得随机数
            e = rng.get_z_range(phi);
            //计算大数e和phi的最大公约数，存于tmp，若e是phi原根，则gcd=1，否则继续循环
            mpz_gcd(tmp.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
        } while (tmp != one);
        //找到e后，使用invert在GMPN库函数找d，使e * d ≡ 1 (mod phi(n))，即e*d与phi互质
        mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
        //写入新的n、e n、d入证书
        ca_cert << n << std::endl << e << std::endl;
        ca_key << n << std::endl << d << std::endl;
        spdlog::info("Generated new RSA key pair and saved to {} and {}", ca_cert_file, ca_key_file);
    }
    else {
        std::ifstream ca_cert(ca_cert_file);
        std::ifstream ca_key(ca_key_file);
        ca_cert >> n >> e;
        ca_key >> n >> d;
        ca_cert.close();
        ca_key.close();
        spdlog::info("Read CA certificate, n = {}, e = {}", n.get_str(16), e.get_str(16));
        spdlog::info("Read CA private key, n = {}, d = {}", n.get_str(16), d.get_str(16));
    }

    mpz_class h_cert = get_hash(cert_n + cert_e);
    mpz_class ca_cert = rsa_decrypt(h_cert, d, n);
    spdlog::info("CA certificate = {}", ca_cert.get_str(16));
    std::ofstream cert_out(cert_file);
    cert_out << cert_n << std::endl << cert_e << std::endl << ca_cert << std::endl;
    return 0;
}
