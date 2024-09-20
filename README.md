# PGP Protocol Implementation in Python

## Overview

This project is an implementation of the **Pretty Good Privacy (PGP)** protocol in **Python**, offering various types of encryption, key management, and secure message transmission between multiple users. PGP is used for securing communications by providing confidentiality, integrity, and authentication.

### Features

- **Encryption Algorithms**: Supports multiple encryption schemes such as:
  - Symmetric encryption (AES, DES, etc.)
  - Asymmetric encryption (RSA)
- **Key Management**:
  - Key generation (public and private keys)
  - Secure key storage and retrieval
- **Message Signing**: Digital signatures to ensure message integrity.
- **Message Encryption**: Encrypt and decrypt messages between multiple users using PGP.
- **User Authentication**: Ensure that messages are sent from verified users.
- **Compression**: Optionally compress messages before encryption to save bandwidth.
- **Integrity Checking**: Provides mechanisms to ensure that messages have not been tampered with.
