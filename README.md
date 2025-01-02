# ECCX

ECCX is a basic python lib modeled after Pretty Good Privacy (PGP), using elliptic curve Diffie-Hellman (ECDH) for key exchange with AES for secure message encryption. 
this library also supports key management, digital signatures, and message verification, for easy and fast encryption and decryption.

## Features

- **Hybrid Encryption**: uses both ECDH and AES encryption for high-level security.
- **Key Management**: supports generation, saving, and loading of private and public keys.
- **Message Signing and Verification**: allows the user to sign messages with private keys and verify those messages using public keys.
- **Basically Zero Requisites**: literally just cryptography and rich. any version that doesn't suck should do.

## Installation
```bash
pip install eccx
```

### Prerequisites
- cryptography (44.0.0 reccomended)
- rich (13.7.1 reccomended)

ensure you have Python 3.6 or higher installed on your system. you can check your Python version by running:

```bash
python --version
```