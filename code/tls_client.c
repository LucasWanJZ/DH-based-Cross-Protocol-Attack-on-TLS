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

    // Create SSL context
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

        if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
            perror("Unable to set minimum protocol version");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);

        return ctx;
    }


    // Create a socket and connect to the server
    int create_socket(char *hostname, int port) {
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
        if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) {
            perror("Invalid address/ Address not supported");
            close(sock);
            exit(EXIT_FAILURE);
        }

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("Connection failed");
            close(sock);
            exit(EXIT_FAILURE);
        }

        return sock;
    }

    int main(int argc, char **argv) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        char *hostname = argv[1];
        int port = atoi(argv[2]);

        initialize_openssl();
        SSL_CTX *ctx = create_context();
        if (SSL_CTX_set_cipher_list(ctx,"DHE-RSA-AES128-SHA256") <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        int server = create_socket(hostname, port);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, server);

        if (SSL_connect(ssl) <= 0) {
            printf("Handshake failed\n");
            ERR_print_errors_fp(stderr);
        } else {
            printf("Handshake finished\n");
            // Print out TLS version
            const char *tls_version = SSL_get_version(ssl);
            printf("TLS version: %s\n", tls_version);
        }

        SSL_free(ssl);
        close(server);
        SSL_CTX_free(ctx);
        cleanup_openssl();

        return 0;
    }
