# DH-based Cross-Protocol Attack on TLS

This repository demonstrates a cross-protocol attack on TLS exploiting a Diffie-Hellman (DH) parameter weakness.

# Requirements:

    OpenSSL 1.1.1 (compiled from source)
    GCC compiler
    Wireshark for network traffic analysis

# How it Works:

## This project implements three C programs:

    mitm: Acts as a Man-in-the-Middle (MitM) server, intercepting communication between client and server.
    tls_server: Simulates a TLS server vulnerable to the DH attack.
    tls_client: A TLS client that connects to the server through the MitM.

## Running the Demonstration:

    Compile the C programs:

    Replace /path/to/openssl-source-code with the actual path to your OpenSSL source code directory:
    Bash

    gcc -o ./mitm mitm.c -I/path/to/openssl-source-code/include  -L/path/to/openssl-source-code/lib -lssl -lcrypto
    gcc -o ./tls_server tls_server.c -I/path/to/openssl-source-code/include  -L/path/to/openssl-source-code/lib -lssl -lcrypto
    gcc -o ./tls_client tls_client.c -I/path/to/openssl-source-code/include  -L/path/to/openssl-source-code/lib -lssl -lcrypto

    Use code with caution.

## Run the programs:

    Start the MitM server:
    Bash

    ./mitm <host> <port> <server_port>

    Use code with caution.

Replace <host> with the desired hostname for the MitM server, <port> with the MitM listening port, and <server_port> with the port the server will communicate with.

```
Start the server:
Bash

./tls_server <host> <server_port>

Use code with caution.
```

Replace <host> with the desired hostname for the server and <server_port> with the port the server will listen on (same as specified in the MitM command).

```
Start the client:
Bash

./tls_client --host <host> --port <mitm_port>

Use code with caution.
```

Replace <host> with the desired hostname for the server (seen from the client's perspective) and <mitm_port> with the port the MitM server is listening on.

## Observe Network Traffic:

  Use Wireshark to capture network traffic while running the programs. You should see communication between the client and the server intercepted by the MitM.

## Disclaimer:

This attack is for educational purposes only. This code should not be used for malicious activities.
