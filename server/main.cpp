#include <fstream>
#include <chrono>
#include <algorithm>
#include"../utils/enctun.hpp"
// #include "../utils/enctun.hpp"

const char default_cert_file[] = "server.pubkey";
const char default_key_file[] = "server.privkey";

gmp_randclass rng(gmp_randinit_default);
mpz_class n, e, d, ca, c_rnd, s_rnd, c_key, pp_rnd, p_key;
unsigned int session_id = 0;

class vpn_session : public std::enable_shared_from_this<vpn_session> {
    public:
        //会话类，处理与客户端的连接
        vpn_session(tcp::socket socket) : socket_(std::move(socket)) {}
        void start() {
            //处理与客户端的异步读取操作
            //记录一个新的连接来自哪个地址
            spdlog::info("New connection from {}", socket_.remote_endpoint().address().to_string());
            socket_.async_read_some(asio::buffer(buffer_), [self = shared_from_this()](std::error_code ec, std::size_t length) {
                if (!ec) {//如果读取操作没有错误（shared_ptr<enctun>类型的ec为空）
                    //将读取的数据转换为字符串
                    std::string message(self->buffer_, length);
                    c_rnd.set_str(message, 16);//使用message来设置c_rnd（客户端随机数）
                    //记录服务器已收到来自客户端的Hello消息
                    spdlog::debug("Client Hello message received, c_rnd = {}", c_rnd.get_str(16));
                    // 发送Server Hello message
                    pb::ServerHello server_hello;//创建了一个ServerHello消息对象
                    s_rnd = rng.get_z_bits(max_prime_bits);//获取长度为max_prime_bits的随机比特串
                    server_hello.set_s_rnd(s_rnd.get_str(16));//设置服务器的随机数s_rnd
                    server_hello.set_n(n.get_str(16));//设置模数n
                    server_hello.set_e(e.get_str(16));//设置公钥指数e
                    server_hello.set_ca(ca.get_str(16));//设置CA证书
                    server_hello.set_sessionid(session_id);//设置会话ID

                    // Client Key Exchange message
                    std::string response;//声明一个字符串response，用于存储服务器hello消息的序列化结果。
                    server_hello.SerializeToString(&response);//将服务器消息对象server_hello序列化为字符串，并将其存储在response中。
                    self->socket_.write_some(asio::buffer(response));//将序列化消息通过套接字写入网络
                    
                    size_t len = self->socket_.read_some(asio::buffer(self->buffer_));//读取数据到缓冲区中，并获取读取的长度。
                    message = std::string(self->buffer_, len);//将读取的数据从self->buffer_转换为字符串message。
                    c_key.set_str(message, 16);//将字符串message转换为mpz_class类型的质数密钥c_key
                    pp_rnd = rsa_decrypt(c_key, d, n);//使用RSA算法解密客户端发送的密钥c_key，解密使用的私钥d和模数n
                    spdlog::debug("Client Key Exchange message received, pp_rnd = {}", pp_rnd.get_str(16));
                    p_key = gen_prime_key(c_rnd, s_rnd, pp_rnd);//证书公钥生成一个质数密钥p_key
                    spdlog::debug("Generated prime key, p_key = {}", p_key.get_str(16));

                    #ifdef REQUIRE_SERVER_HANDSHAKE
                    mpz_class h_p_key = get_hash(p_key);
                    self->socket_.write_some(asio::buffer(h_p_key.get_str(16), h_p_key.get_str(16).size() + 1));
                    #endif

                    char p_buffer[buffer_size];
                    char nonce[nonce_bits];
                    char key[key_bits];
                    static_assert(buffer_size >= max_prime_bits, "buffer_size must be greater than max_prime_bits");
                    mpz_export(p_buffer, nullptr, 1, 1, 0, 0, p_key.get_mpz_t());
                    std::copy(p_buffer, p_buffer + nonce_bits, nonce);
                    std::copy(p_buffer +( max_prime_bits >> 3) - key_bits, p_buffer + (max_prime_bits >> 3), key);

                    // self->chacha = std::make_unique<Chacha20>(key, nonce, session_id);
                    // len = self->socket_.read_some(asio::buffer(self->buffer_));
                    // message = std::string(self->buffer_, len);
                    // self->chacha->crypt(reinterpret_cast<uint8_t*>(message.data()), message.size());
                    // spdlog::info("Received message: {}", message);

                    self->ec = std::make_shared<enctun>(std::move(self->socket_), key, nonce, session_id, buffer_size);
                    self->ec->run();

                    session_id++;
                }
            });
        }

    private:

        tcp::socket socket_;
        char buffer_[buffer_size];
        std::shared_ptr<enctun> ec;
};

//----------------------------------------------------------------------

awaitable<void> listener(tcp::acceptor acceptor) {
    for (;;) {
        std::make_shared<vpn_session>(co_await acceptor.async_accept(use_awaitable))
            ->start();
    }
}

//----------------------------------------------------------------------

int main(int argc, char *argv[]) {
    try {
        if (argc < 2 || argc > 4) {// 检查命令行参数个数，如果小于2或大于4，则输出错误信息并退出程序。
            spdlog::error("Usage: server <port> [<cert_file> <key_file>]");
            spdlog::error("  Default cert_file: {}", default_cert_file);
            spdlog::error("  Default key_file: {}", default_key_file);
            return 1;
        }
        // 如果定义了HELLO_MSG宏，则执行tun_init()函数来初始化虚拟网络接口。
        #ifndef HELLO_MSG
        tun_init();
        #endif
        // 构建证书文件名，如果指定了命令行参数，则使用参数值，否则使用默认值。
        std::string cert_file(argc > 2 ? argv[2] : default_cert_file);
        std::string key_file(argc > 3 ? argv[3] : default_key_file);
        // 检查证书和密钥文件是否存在，如果不存在，则创建它们。
        if (!std::ifstream(cert_file) || !std::ifstream(key_file)) {
            std::ofstream cert(cert_file);
            std::ofstream key(key_file);
            // 创建大整数类型的p、q、inv和phi变量。
            mpz_class p, q, inv, phi;
            mpz_class one = 1;//初始化一个值为1的大整数one。
            // 从随机数生成器获取指定位数的大素数p和q。
            mpz_class tmp_p = rng.get_z_bits(max_prime_bits);
            mpz_class tmp_q = rng.get_z_bits(max_prime_bits);
            // 找到下一个素数作为p和q。
            mpz_nextprime(p.get_mpz_t(), tmp_p.get_mpz_t());
            mpz_nextprime(q.get_mpz_t(), tmp_q.get_mpz_t());
            // 计算n（模数）和phi（欧拉函数值）。
            n = p * q;
            phi = (p - one) * (q - one);
            // find a number e such that 1 < e < phi and gcd(e, phi) = 1
            mpz_class tmp;
            do {// 找到一个满足条件的e值，即1 < e < phi且e和phi互质。
                e = rng.get_z_range(phi);
                //计算大数tmp和e的最大公约数，并存储在tmp
                mpz_gcd(tmp.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
            } while (tmp != one);//若tmp为1则互质成功
            mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());// 计算d的值，使得e*d mod phi = 1。
            cert << n << std::endl << e << std::endl << 0 << std::endl;// 将n、e和d写入证书文件。
            key << n << std::endl << d << std::endl;// 将n和d写入密钥文件
            // 提示用户可能需要生成CA证书并签发服务器证书。
            spdlog::info("Generated new RSA key pair and saved to {} and {}", cert_file, key_file);
            spdlog::info("You may need to generate a CA certificate and sign the server certificate");
        }
        else {
            std::ifstream cert(cert_file);
            std::ifstream key(key_file);
            cert >> n >> e >> ca;
            key >> n >> d;
            spdlog::info("Using existing RSA key pair from {} and {}", cert_file, key_file);
        }

        rng.seed((unsigned long)std::chrono::system_clock::now().time_since_epoch().count());

        asio::io_context io_context(1);

        unsigned short port = std::atoi(argv[1]);
        co_spawn(io_context,
                listener(tcp::acceptor(io_context, {tcp::v4(), port})),
                detached);

        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto) {
            io_context.stop();
            #ifndef HELLO_MSG
            tun_stop();
            #endif
        });

        io_context.run();
    } catch (std::exception &e) {
        spdlog::error("Exception: {}", e.what());
    }

    spdlog::debug("Server stopped");

    return 0;
}