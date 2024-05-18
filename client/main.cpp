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
            spdlog::error("Usage: client <addr> <port> [ca_cert_file]");
            return 1;
        }

        #ifndef HELLO_MSG
        tun_init();
        #endif

        std::string address = argv[1];
        unsigned short port_number = std::atoi(argv[2]);
        std::string ca_cert_file = argc == 4 ? argv[3] : default_ca_cert_file;
        std::ifstream ca_cert(ca_cert_file);
        if (!ca_cert) {
            spdlog::error("Cannot open ca_cert_file {}", ca_cert_file);
            return 1;
        }
        ca_cert >> ca_n >> ca_e;
        spdlog::debug("Read CA certificate, ca_n = {}, ca_e = {}", ca_n.get_str(16), ca_e.get_str(16));
        ca_cert.close();

        asio::io_context io_context;

        // Create a TCP socket
        asio::ip::tcp::socket socket(io_context);

        // Connect to the server
        asio::ip::tcp::endpoint endpoint(asio::ip::address::from_string(address), asio::ip::port_type(port_number));
        socket.connect(endpoint);

        gmp_randclass rng(gmp_randinit_default);
        rng.seed((unsigned long)std::chrono::system_clock::now().time_since_epoch().count());

        // Client Hello message
        c_rnd = rng.get_z_bits(max_prime_bits);
        socket.write_some(asio::buffer(c_rnd.get_str(16).c_str(), c_rnd.get_str(16).size() + 1));
        spdlog::debug("Sent Client Hello message, c_rnd = {}", c_rnd.get_str(16));

        // Server Hello message
        socket.read_some(asio::buffer(buffer, buffer_size));
        std::string message(buffer);
        pb::ServerHello server_hello;
        server_hello.ParseFromString(message);
        s_rnd.set_str(server_hello.s_rnd(), 16);
        n.set_str(server_hello.n(), 16);
        e.set_str(server_hello.e(), 16);
        ca.set_str(server_hello.ca(), 16);
        session_id = server_hello.sessionid();
        spdlog::debug("Received Server Hello message, s_rnd = {}, n = {}, e = {}, ca = {}, session_id = {}",
                        s_rnd.get_str(16), n.get_str(16), e.get_str(16), ca.get_str(16), session_id);
        
        mpz_class h_cert = get_hash(n + e);
        mpz_class h_ca_cert = rsa_encrypt(ca, ca_e, ca_n);
        if (h_cert != h_ca_cert) {
            spdlog::error("CA certificate verification failed");
            socket.close();
            return 1;
        }
        else spdlog::debug("CA certificate verification success");

        // Client Key Exchange message
        pp_rnd = rng.get_z_bits(max_prime_bits);
        mpz_class c_key = rsa_encrypt(pp_rnd, e, n);
        socket.write_some(asio::buffer(c_key.get_str(16).c_str(), c_key.get_str(16).size() + 1));
        spdlog::debug("Sent Client Key Exchange message, pp_rnd = {}", pp_rnd.get_str(16));

        p_key = gen_prime_key(c_rnd, s_rnd, pp_rnd);
        spdlog::debug("Generated prime key, p_key = {}", p_key.get_str(16));

        static_assert(buffer_size >= max_prime_bits, "buffer_size must be greater than max_prime_bits");
        mpz_export(buffer, nullptr, 1, 1, 0, 0, p_key.get_mpz_t());
        std::copy(buffer, buffer + nonce_bits, nonce);
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

        ec = std::make_shared<enctun>(std::move(socket), key, nonce, session_id, buffer_size);
        ec->run();

        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto){
            io_context.stop();
            #ifndef HELLO_MSG
            tun_stop();
            #endif
        });

        io_context.run();
    } catch (const std::exception& e) {
        spdlog::error("Exception: {}", e.what());
    }

    spdlog::debug("Client stopped");

    return 0;
}