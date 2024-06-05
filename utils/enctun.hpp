#include "tun.hpp"
#include "crypto.hpp"
#include <deque>

#ifdef USE_ZSTD
#include <zstd.h>
#endif
//enctun: 这个类代表了一个加密的隧道，它处理数据的加密和解密。
class enctun : public std::enable_shared_from_this<enctun> {
    public:
    //构造函数，接收一个 TCP 套接字，密钥，nonce 值，计数器和缓冲区大小，
    //初始化加密和解密用的 Chacha20 对象，并分配缓冲区。
    //nonce（Number Once）是一个在加密会话中只使用一次的随机数或计数器值。它的目的是增加通信的安全性，防止重放攻击（replay attacks）。在 VPN 场景中，nonce 通常用于初始化向量（Initialization Vector, IV）的生成，或者是用于提供会话之间的唯一性。
    //ChaCha20 是一个块密码算法，它需要一个 nonce 值和一个初始化向量（IV）来生成密文。这个 nonce 值和密钥一起用来确保每次加密都是唯一的，即使两次传输的数据相同，由于 nonce 值的不同，生成的密文也会不同。
        enctun(asio::ip::tcp::socket socket, const char key[32], const char nonce[8], uint64_t counter, size_t buffer_size) : 
        socket(std::move(socket)), buffer_size(buffer_size), enc_chacha(key, nonce, counter), dec_chacha(key, nonce, counter) {
            enc_buffer = new unsigned char[buffer_size];
            dec_buffer = new unsigned char[buffer_size];
            #ifdef USE_ZSTD
            zstd_enc_buffer = new unsigned char[buffer_size];
            zstd_dec_buffer = new unsigned char[buffer_size];
            #endif
            is_running = true;
        }

        ~enctun() {// 析构函数，确保在对象销毁前关闭套接字并释放分配的资源。
            stop();
        }
        // void run():启动加密隧道，在一个循环中持续读取和写入数据
        void run() {
            while (is_running) {
                #ifdef HELLO_MSG
                if (socket.is_open()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    std::string message = "Hello, world!";
                    size_t size = message.size();
                    std::copy(message.begin(), message.end(), enc_buffer);
                #else
                if (is_tun_has_data()) {
                    size_t size = tun_read(enc_buffer, buffer_size);//如果隧道里有数据，读取size个数据
                #endif
                    //对数据进行Chacha20方法加密，enc_buffer存储加密size后的数组
                    enc_chacha.crypt(reinterpret_cast<uint8_t*>(enc_buffer), size);
                    #ifdef USE_ZSTD //如果定义了USE_ZSTD宏，则使用Zstandard压缩库
                    //压缩加密后的数据，zstd_enc_buffer存储压缩后的字节数组，压缩后的大小为buffer_size
                    size = ZSTD_compress(zstd_enc_buffer, buffer_size, enc_buffer, size, 1);
                    socket.write_some(asio::buffer(zstd_enc_buffer, size));
                    #else
                    socket.write_some(asio::buffer(enc_buffer, size));//创建缓冲区，异步发送数据到socket
                    #endif
                }
                else break;

                if (socket.available() > 0) {//如果socket有数据等待读取
					size_t size = socket.read_some(asio::buffer(dec_buffer, buffer_size));
                    #ifdef USE_ZSTD//和上面一样，若定义了ZSTD宏则使用其库的解压缩函数
                    size = ZSTD_decompress(zstd_dec_buffer, buffer_size, dec_buffer, size);
                    //对解压缩后的数据进行chacha方法解密
                    dec_chacha.crypt(reinterpret_cast<uint8_t*>(zstd_dec_buffer), size);
                    //将字节数据转为string类型，方便处理和显示
                    std::string message((char*)zstd_dec_buffer, size);
                    #else
					dec_chacha.crypt(reinterpret_cast<uint8_t*>(dec_buffer), size);
					std::string message((char*)dec_buffer, size);
                    #endif
                    #ifdef HELLO_MSG //要么打印欢迎消息
					spdlog::info("Received message: {}", message);
                    #else
                    //否则将解加密和解压缩后的数据写入虚拟隧道接口（Tunnel Interface）。这是 VPN 客户端接收到的原始数据，并将它们转发到本地网络或客户端。
                    tun_write(dec_buffer, size);
                    #endif
				}
            }   
            stop();
        }
    private:
        void stop() {
            socket.close();
            delete[] enc_buffer;
            delete[] dec_buffer;
            #ifdef USE_ZSTD
            delete[] zstd_enc_buffer;
            delete[] zstd_dec_buffer;
            #endif
        }   
    size_t buffer_size;//buffer_size: 缓冲区大小。
    unsigned char *enc_buffer;//enc_buffer 和 dec_buffer: 分别用于存储加密和解密后的数据
    unsigned char *dec_buffer;
    #ifdef USE_ZSTD
    unsigned char *zstd_enc_buffer;//zstd_enc_buffer 和 zstd_dec_buffer: 
    unsigned char *zstd_dec_buffer;//如果启用了 Zstandard 压缩库，则用于存储压缩和解压后的数据。
    #endif
    asio::ip::tcp::socket socket;//socket: TCP 套接字，用于网络通信。
    Chacha20 enc_chacha;//enc_chacha 和 dec_chacha: Chacha20 加密对象，用于数据的加密和解密。
    Chacha20 dec_chacha;
    bool is_running;//is_running: 一个布尔值，用于标识隧道是否正在运行。
};
/*
代码逻辑
隧道启用 Zstandard 压缩（如果定义了 USE_ZSTD）
在一个循环中，首先检查 TCP 套接字是否打开。
如果套接字打开，或者定义了 HELLO_MSG，则读取数据。
对于每个读取操作，将数据加密。
使用 Zstandard 压缩库压缩数据，然后写入套接字。
如果套接字有数据可读，则读取并解密数据。
如果是 Zstandard 压缩的数据，先解压缩。
打印接收到的消息（如果定义了 HELLO_MSG），或者将解密后的数据写入 tun 接口。
一些注意点
#ifdef USE_ZSTD 和 #else 指令是条件编译指令，用于在编译时决定是否使用 Zstandard 压缩库。
#ifdef HELLO_MSG 是另一个条件编译指令，用于在编译时决定是否处理一个简单的 “Hello, world!” 消息。
该程序使用 ChaCha20 加密算法和可能的 Zstandard 压缩来加密和解密通过 TCP 连接传输的数据。
*/