#include <fstream>
#include <chrono>
#include <algorithm>
#include "../utils/enctun.hpp"

mpz_class n, e, ca, ca_n, ca_e, c_rnd, s_rnd, pp_rnd, p_key;
char buffer[buffer_size];
char nonce[nonce_bits];
char key[key_bits];
unsigned int session_id = 0;

const char default_ca_cert_file[] = "ca.pubkey";

std::shared_ptr<enctun> ec;

int main(int argc, char *argv[]) {
    try {
        if (argc < 3 || argc > 4) {
            //命令行执行client.exe需传入address port ca_cert_file三个参数
            spdlog::error("Usage: client <addr> <port> [ca_cert_file]");
            return 1;
        }

        #ifndef HELLO_MSG
        tun_init();//若未定义宏则初始化tun网络地址设备
        #endif
                                
        std::string address = argv[1];
        unsigned short port_number = std::atoi(argv[2]);
        std::string ca_cert_file = argc == 4 ? argv[3] : default_ca_cert_file;
        std::ifstream ca_cert(ca_cert_file);//用户提供的CA证书文件
        if (!ca_cert) {
            spdlog::error("Cannot open ca_cert_file {}", ca_cert_file);
            return 1;
        }
        ca_cert >> ca_n >> ca_e;//从CA证书文件中读取证书的公共密钥的模数（ca_n）和指数（ca_e），并关闭文件。
        spdlog::debug("Read CA certificate, ca_n = {}, ca_e = {}", ca_n.get_str(16), ca_e.get_str(16));
        ca_cert.close();

        asio::io_context io_context;//创建一个Asio网络通信的上下文对象，用于管理IO操作。
        asio::ip::tcp::socket socket(io_context);//在上下文对象中创建一个TCP套接字。
        //使用提供的地址和端口号创建异步tcp IO端点，然后将套接字连接到这个端点。
        asio::ip::tcp::endpoint endpoint(asio::ip::address::from_string(address), asio::ip::port_type(port_number));
        socket.connect(endpoint);

        gmp_randclass rng(gmp_randinit_default);//创建一个GMPRandom数生成器对象rng，使用默认的随机数初始化方法。
        //使用当前时间的毫秒数作为种子来初始化随机数生成器，这样可以保证每次运行程序时生成的随机数序列不同。
        rng.seed((unsigned long)std::chrono::system_clock::now().time_since_epoch().count());

        // Client Hello message
        c_rnd = rng.get_z_bits(max_prime_bits);//生成一个随机的大整数c_rnd，其位数不超过max_prime_bits。这个随机数将用于客户端的Hello消息。
        socket.write_some(asio::buffer(c_rnd.get_str(16).c_str(), c_rnd.get_str(16).size() + 1));//将c_rnd转换为字符串，并使用Asio的write_some函数将其发送到服务器。
        spdlog::debug("Sent Client Hello message, c_rnd = {}", c_rnd.get_str(16));//打印调试信息，表明客户端Hello消息已发送。

        // Server Hello message
        socket.read_some(asio::buffer(buffer, buffer_size));//从服务器读取一些数据到缓冲区buffer中。
        std::string message(buffer);//将读取的数据转换为字符串message。
        pb::ServerHello server_hello;//定义一个 Protocol Buffers（protobuf）格式的ServerHello消息对象server_hello。
        server_hello.ParseFromString(message);//将接收到的字符串解析为ServerHello消息。

        s_rnd.set_str(server_hello.s_rnd(), 16);//从ServerHello消息中提取所需的参数，如服务器随机数s_rnd、模数n、公钥指数e、CA证书ca和会话IDsession_id。
        n.set_str(server_hello.n(), 16);
        e.set_str(server_hello.e(), 16);
        ca.set_str(server_hello.ca(), 16);
        session_id = server_hello.sessionid();
        spdlog::debug("Received Server Hello message, s_rnd = {}, n = {}, e = {}, ca = {}, session_id = {}",
                        s_rnd.get_str(16), n.get_str(16), e.get_str(16), ca.get_str(16), session_id);
        mpz_class h_ca_cert = rsa_encrypt(ca, ca_e, ca_n);//使用RSA加密算法对CA证书进行解密，得到h_ca_cert。
        mpz_class h_cert = get_hash(n + e);//计算证书的哈希值h_cert，这是通过将证书的模数n和公钥指数e相加然后进行哈希得到的。
        if (h_cert != h_ca_cert) {//比较计算出的哈希值h_cert和加密后的哈希值h_ca_cert。如果不相等，则证书验证失败，并打印错误信息；否则验证成功。
            spdlog::error("CA certificate verification failed");
            socket.close();
            return 1;
        }
        else spdlog::debug("CA certificate verification success");

        // Client Key Exchange message
        pp_rnd = rng.get_z_bits(max_prime_bits);//获取指定位数的随机数
        mpz_class c_key = rsa_encrypt(pp_rnd, e, n);//使用证书公钥和RSA算法加密密钥
        //将密钥异步写入套接字
        socket.write_some(asio::buffer(c_key.get_str(16).c_str(), c_key.get_str(16).size() + 1));
        spdlog::debug("Sent Client Key Exchange message, pp_rnd = {}", pp_rnd.get_str(16));

        p_key = gen_prime_key(c_rnd, s_rnd, pp_rnd);//随机数1、2、3生成会话密钥
        spdlog::debug("Generated prime key, p_key = {}", p_key.get_str(16));//记录生成的质数密钥
        // 静态断言确保缓冲区大小足够大
        static_assert(buffer_size >= max_prime_bits, "buffer_size must be greater than max_prime_bits");
        //将大整数导出到字节数组，1, 1表示以二进制形式导出，0, 0表示不需要任何其他额外信息
        mpz_export(buffer, nullptr, 1, 1, 0, 0, p_key.get_mpz_t());
        // 复制buffer数组的前nonce_bits位到nonce数组
        std::copy(buffer, buffer + nonce_bits, nonce);
        // 复制buffer数组中剩余的部分到key数组
        std::copy(buffer + (max_prime_bits >> 3) - key_bits, buffer + (max_prime_bits >> 3), key);

        // std::string message_buffer = "Hello, world!";
        // chacha.crypt(reinterpret_cast<uint8_t*>(message_buffer.data()), message_buffer.size());
        // socket.write_some(asio::buffer(message_buffer, message_buffer.size()));

        #ifdef REQUIRE_SERVER_HANDSHAKE
        size_t len = socket.read_some(asio::buffer(buffer, buffer_size));
        message = std::string(buffer, len);
        mpz_class h_p_key;
        h_p_key.set_str(message, 16);
        if (h_p_key != get_hash(p_key)) {
            spdlog::error("Server handshake failed");
            socket.close();
            return 1;
        }
        spdlog::info("Server handshake successful");
        #endif
// 创建一个共享的 `enctun` 对象实例。`enctun` 可能是一个自定义类，负责加密和解密流量。
// `std::move(socket)` 将网络套接字移动到 `enctun` 对象中，这样套接字的所有权就转移了。
// `key` 是客户端用服务器公钥加密的密钥，用于后续的加密通信。
// `nonce` 是一个一次性使用的随机数，用于增强安全性。
// `session_id` 可能是用于识别会话的唯一标识符。
// `buffer_size` 是通信时使用的缓冲区大小。
        ec = std::make_shared<enctun>(std::move(socket), key, nonce, session_id, buffer_size);
        ec->run();//启动 `enctun` 对象的运行，包括设置加密通道，监听客户端请求等
        // 异步等待上述信号集中的信号。当信号到来时，会执行回调函数。
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto){
            io_context.stop();// 停止 Asio 事件循环，这将导致服务器关闭。
            #ifndef HELLO_MSG
            tun_stop();// 停止虚拟隧道设备，清理资源。
            #endif
        });//启动 Asio 服务器的事件循环，等待网络事件和信号事件。服务器会一直运行，直到事件循环被停止
        io_context.run();
    } catch (const std::exception& e) {
        spdlog::error("Exception: {}", e.what());
    }

    spdlog::debug("Client stopped");

    return 0;
}