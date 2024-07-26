    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <openssl/ssl.h>
    #include <openssl/ssl3.h>
    #include <openssl/err.h>
    #include <openssl/evp.h>
    #include <openssl/bn.h>
    #include <openssl/x509.h>
    #include <openssl/ec.h>

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

        method = SSLv23_server_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) {
            perror("Unable to create SSL context");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);
        return ctx;
    }


  void configure_context(SSL_CTX *ctx) {
        if (SSL_CTX_use_certificate_file(ctx, "private_files/server.crt", SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, "private_files/server.key", SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256") <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_set1_curves_list(ctx, "secp384r1") != 1) {
            perror("Unable to set curves list");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        // Load DH parameters
        DH *dh = NULL;
        FILE *dh_params = fopen("private_files/dhparam.pem", "r");
        if (dh_params) {
            dh = PEM_read_DHparams(dh_params, NULL, NULL, NULL);
            fclose(dh_params);
        } else {
            perror("Unable to open DH parameters file");
            exit(EXIT_FAILURE);
        }

        if (dh == NULL) {
            perror("Unable to read DH parameters");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_set_tmp_dh(ctx, dh) <= 0) {
            perror("Unable to set DH parameters");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        DH_free(dh);
    }

    // Create a socket and bind to the host and port
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
        if (argc != 3) {
            fprintf(stderr, "Usage: %s <host> <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        const char *host = argv[1];
        int port = atoi(argv[2]);

        initialize_openssl();
        SSL_CTX *ctx = create_context();
        configure_context(ctx);

        int server_sock = create_socket(host, port);

        while (1) {
            struct sockaddr_in addr;
            uint len = sizeof(addr);
            SSL *ssl;

            int client_sock = accept(server_sock, (struct sockaddr*)&addr, &len);
            if (client_sock < 0) {
                perror("Unable to accept");
                close(server_sock);
                SSL_CTX_free(ctx);
                cleanup_openssl();
                exit(EXIT_FAILURE);
            }

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_sock);

            if (SSL_accept(ssl) <= 0) {
                printf("Handshake failed\n");
                ERR_print_errors_fp(stderr);
            } else {
                printf("Handshake finished\n");
               
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_sock);
        }

        close(server_sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();

        return 0;
    }
