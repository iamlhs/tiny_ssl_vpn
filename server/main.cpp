#include <fstream>
#include <chrono>
#include <algorithm>
#include "../utils/enctun.hpp"

const char default_cert_file[] = "server.pubkey";
const char default_key_file[] = "server.privkey";

gmp_randclass rng(gmp_randinit_default);
mpz_class n, e, d, ca, c_rnd, s_rnd, c_key, pp_rnd, p_key;
unsigned int session_id = 0;

class vpn_session : public std::enable_shared_from_this<vpn_session> {
    public:
        vpn_session(tcp::socket socket) : socket_(std::move(socket)) {}

        void start() {
            spdlog::info("New connection from {}", socket_.remote_endpoint().address().to_string());
            socket_.async_read_some(asio::buffer(buffer_), [self = shared_from_this()](std::error_code ec, std::size_t length) {
                if (!ec) {
                    std::string message(self->buffer_, length);
                    c_rnd.set_str(message, 16);
                    spdlog::debug("Client Hello message received, c_rnd = {}", c_rnd.get_str(16));
                    // Server Hello message
                    pb::ServerHello server_hello;
                    s_rnd = rng.get_z_bits(max_prime_bits);
                    server_hello.set_s_rnd(s_rnd.get_str(16));
                    server_hello.set_n(n.get_str(16));
                    server_hello.set_e(e.get_str(16));
                    server_hello.set_ca(ca.get_str(16));
                    server_hello.set_sessionid(session_id);

                    // Client Key Exchange message
                    std::string response;
                    server_hello.SerializeToString(&response);
                    self->socket_.write_some(asio::buffer(response));
                    size_t len = self->socket_.read_some(asio::buffer(self->buffer_));
                    message = std::string(self->buffer_, len);
                    c_key.set_str(message, 16);
                    pp_rnd = rsa_decrypt(c_key, d, n);
                    spdlog::debug("Client Key Exchange message received, pp_rnd = {}", pp_rnd.get_str(16));
                    p_key = gen_prime_key(c_rnd, s_rnd, pp_rnd);
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
        if (argc < 2 || argc > 4) {
            spdlog::error("Usage: server <port> [<cert_file> <key_file>]");
            spdlog::error("  Default cert_file: {}", default_cert_file);
            spdlog::error("  Default key_file: {}", default_key_file);
            return 1;
        }

        #ifndef HELLO_MSG
        tun_init();
        #endif

        std::string cert_file(argc > 2 ? argv[2] : default_cert_file);
        std::string key_file(argc > 3 ? argv[3] : default_key_file);

        if (!std::ifstream(cert_file) || !std::ifstream(key_file)) {
            std::ofstream cert(cert_file);
            std::ofstream key(key_file);
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
            do {
                e = rng.get_z_range(phi);
                mpz_gcd(tmp.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
            } while (tmp != one);
            mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
            cert << n << std::endl << e << std::endl << 0 << std::endl;
            key << n << std::endl << d << std::endl;
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