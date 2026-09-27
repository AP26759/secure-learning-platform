# Secure Learning Platform

A security-focused learning platform developed in Python to demonstrate secure application design, authentication, role-based access control, cryptographic data protection, secure communication, auditing, and automated security testing.

The project applies multiple security controls to protect users and sensitive academic information while demonstrating how cryptographic and access-control mechanisms can be integrated into an application.

## Overview

The Secure Learning Platform models an educational system containing different types of users and sensitive academic information.

Rather than relying on a single security mechanism, the application combines authentication, authorisation, encryption, integrity protection, digital signatures, session management, auditing, and automated testing.

The project is organised into dedicated security components:

```text
Authentication
      ↓
Session Management
      ↓
Role-Based Access Control
      ↓
Cryptographic Protection
      ↓
Protected Application Data
      ↓
Audit Logging
      ↓
Security Testing
```

## Security Features

### Authentication

User authentication is handled through a dedicated authentication component.

Passwords are not stored directly. Password-based key derivation is performed using PBKDF2-HMAC-SHA256, allowing passwords to be securely verified without retaining their plaintext values.

The authentication system also implements account lockout behaviour to reduce the effectiveness of repeated password-guessing attempts.

### Secure Session Management

Authenticated users receive securely generated session tokens.

Sessions are validated before protected operations are performed and can be invalidated when the user logs out.

This separates authentication from subsequent access decisions and prevents protected operations from relying directly on supplied usernames.

### Role-Based Access Control

The platform implements Role-Based Access Control (RBAC) to restrict functionality according to the user's assigned role.

The application contains roles representing:

- Students
- Lecturers
- Administrators

Authorisation checks are performed before protected operations, limiting users to actions appropriate for their role.

### AES-256-GCM Encryption

Sensitive application data is protected using AES-256-GCM authenticated encryption.

AES-GCM provides both confidentiality and authentication, allowing the application to detect modifications to encrypted data while preventing its contents from being read without the appropriate key.

### RSA Cryptography

The application uses RSA-2048 public-key cryptography for operations requiring asymmetric protection.

RSA-OAEP is used where asymmetric encryption is required, providing a secure padding scheme for RSA encryption.

### Digital Signatures

RSA-PSS digital signatures are used to protect the authenticity and integrity of security-sensitive information.

Signatures allow the platform to verify that protected information was created by the expected entity and has not subsequently been modified.

### Integrity Protection

HMAC-based integrity checks are used to detect unauthorised modifications to protected data.

This provides an additional mechanism for verifying that stored or transmitted information has not been altered.

### Protected Academic Data

Sensitive information such as grades is cryptographically protected rather than being stored directly as plaintext.

The platform combines encryption, integrity protection, and digital signatures to provide multiple layers of protection for academic records.

### Secure Messaging

The application includes secure messaging functionality using cryptographic controls to protect communication between users.

This demonstrates the use of asymmetric and symmetric cryptographic techniques within an application workflow rather than as isolated examples.

### Key Revocation

The cryptographic component includes support for key revocation, allowing compromised or invalid cryptographic identities to be rejected.

### Audit Logging

Security-relevant application events are recorded to provide traceability and accountability.

Audit records can be used to investigate authentication activity and other security-sensitive operations.

## Project Structure

```text
secure-learning-platform/
│
├── auth/
│   └── auth_manager.py
│
├── crypto/
│   └── data_protector.py
│
├── data/
│   └── platform_data.py
│
├── rbac/
│   └── access_control.py
│
├── tests/
│   └── test_platform.py
│
├── ui/
│   └── cli.py
│
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

### `auth/`

Handles user authentication, password protection, session management and authentication-related security controls.

### `crypto/`

Contains the cryptographic functionality used by the application, including encryption, integrity protection, asymmetric cryptography and digital signatures.

### `rbac/`

Implements the platform's role-based access-control rules and authorisation decisions.

### `data/`

Handles protected application data and the interaction between application functionality and the security components.

### `ui/`

Provides the command-line interface used to interact with the platform.

### `tests/`

Contains the automated test suite covering application functionality and security controls.

## Automated Security Testing

The project contains an extensive automated test suite covering both normal functionality and security behaviour.

The tests include areas such as:

- Password hashing and verification
- Authentication
- Account lockout
- Session handling
- Role-based access control
- AES encryption and decryption
- Encryption tamper detection
- HMAC integrity verification
- RSA cryptography
- Digital signatures
- Protected academic records
- Secure messaging
- User isolation
- Session invalidation

Tests can be executed using:

```bash
python -m pytest tests/
```

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/secure-learning-platform.git
cd secure-learning-platform
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Linux/macOS:

```bash
source .venv/bin/activate
```

Or on Windows:

```powershell
.venv\Scripts\activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

Start the platform using:

```bash
python main.py
```

The application provides a command-line interface for interacting with the learning platform and its security functionality.

## Running the Tests

Install the required dependencies and run:

```bash
python -m pytest tests/
```

The test suite validates both application behaviour and the implemented security controls.

## Cryptographic Design

The project uses several cryptographic mechanisms for different security requirements:

| Mechanism | Purpose |
|---|---|
| PBKDF2-HMAC-SHA256 | Password protection |
| AES-256-GCM | Authenticated symmetric encryption |
| RSA-2048 | Public-key cryptography |
| RSA-OAEP | RSA encryption |
| RSA-PSS | Digital signatures |
| HMAC | Integrity verification |
| Secure random tokens | Session management |

Using separate cryptographic mechanisms for confidentiality, authentication and integrity demonstrates the importance of selecting controls according to the security property being protected.

## Security Architecture

The platform follows a defence-in-depth approach:

```text
User
 │
 ▼
Authentication
 │
 ▼
Secure Session
 │
 ▼
RBAC Authorisation
 │
 ▼
Application Operation
 │
 ├──── AES Encryption
 ├──── RSA Cryptography
 ├──── Digital Signatures
 ├──── HMAC Integrity
 │
 ▼
Protected Data
 │
 ▼
Audit Logging
```

A compromise or failure of one control therefore does not necessarily remove every layer of protection around sensitive application data.

## Security Considerations

This project is intended as a security-focused prototype and learning platform rather than a production deployment.

Cryptographic key material is generated and stored locally by the application. A production system should use dedicated key-management infrastructure such as a hardware security module (HSM), cloud key-management service, or dedicated secrets-management platform.

Runtime-generated cryptographic keys, user data, encrypted records and logs are excluded from version control through `.gitignore`.

Any example accounts or credentials included for demonstration purposes are intended only for local testing and should not be reused in a production environment.

## Technologies

- Python
- `cryptography`
- AES-256-GCM
- RSA-2048
- RSA-OAEP
- RSA-PSS
- PBKDF2-HMAC-SHA256
- HMAC
- Role-Based Access Control
- Pytest

## What This Project Demonstrates

This project demonstrates practical experience with:

- Secure software design
- Authentication and session management
- Password security
- Access-control implementation
- Symmetric and asymmetric cryptography
- Authenticated encryption
- Digital signatures
- Integrity protection
- Security auditing
- Automated security testing
- Defence-in-depth design

## Purpose

This project was developed as part of my practical cybersecurity work and demonstrates the application of security engineering principles within a Python application.

The repository has been prepared as a portfolio version of the original project and focuses on the technical implementation, security architecture, and testing.
