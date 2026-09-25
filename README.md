# ics0022
# Password Manager

A command-line password manager developed as a security-focused university project.

## Scope

The application will securely store user credentials in an encrypted vault.

The initial version will include:

* Master password authentication
* Secure key derivation using Argon2id
* Vault encryption using AES-256-GCM
* Encrypted local vault storage
* Adding, viewing, editing and deleting password entries
* Basic input validation
* Locking the vault when it is no longer needed

The initial version will not include:

* Cloud synchronization
* Multi-device synchronization
* Browser extensions
* Password sharing
* Hardware security modules (HSM)

## Planned Commands

The command-line interface is planned to support:

| Command  | Description                                |
| -------- | ------------------------------------------ |
| `init`   | Create a new password vault                |
| `unlock` | Unlock the vault using the master password |
| `add`    | Add a new password entry                   |
| `list`   | List stored entries                        |
| `get`    | View a specific password entry             |
| `edit`   | Edit an existing entry                     |
| `delete` | Delete an entry                            |
| `lock`   | Lock the vault                             |
| `exit`   | Exit the application                       |

## Planned Screens / Interface

The application will initially use a CLI interface.

Planned screens:

1. **Main menu**

   * Unlock vault
   * Create vault
   * Exit

2. **Unlocked vault menu**

   * Add entry
   * List entries
   * Get entry
   * Edit entry
   * Delete entry
   * Lock vault
   * Exit

3. **Password input**

   * Master password input will not be displayed in plaintext.

## Architecture

The system is divided into four main modules:

* **User Management Module** – handles master password authentication and key derivation.
* **Encryption Module** – encrypts and decrypts the vault using AES-256-GCM.
* **Storage Layer** – reads and writes the encrypted vault file.
* **User Interface** – provides the command-line interface.

The general data flow is:

`Master Password → Argon2id → Encryption Key → AES-256-GCM → Encrypted Vault → vault.enc`

## Vault Format

The vault will be stored as an encrypted file named `vault.enc`.

The encrypted file will contain:

* Format/version information
* Argon2id parameters
* Random salt
* Random nonce
* Ciphertext
* Authentication tag

The plaintext vault data will use a structured format such as JSON before encryption.

## Cryptographic Design

The planned cryptographic scheme is:

**Argon2id → 256-bit key → AES-256-GCM**

A unique random salt will be generated for each vault. AES-GCM will provide both confidentiality and integrity protection.

The master password itself will not be stored in the vault.

## Build and Run

The project is planned to use CMake.

Example build commands:

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

Run the application with:

```bash
./password-manager
```

On Windows, the executable may be run from the generated build directory.

## Repository Structure

```text
password-manager/
├── README.md
├── DESIGN.md
├── .gitignore
├── src/
│   ├── main.cpp
│   ├── encryption/
│   │   ├── encryption.cpp
│   │   └── encryption.h
│   ├── user/
│   │   ├── user.cpp
│   │   └── user.h
│   ├── storage/
│   │   ├── storage.cpp
│   │   └── storage.h
│   └── interface/
│       ├── cli.cpp
│       └── cli.h
├── tests/
└── vault/
    └── .gitkeep
```

## Security Assumptions

The initial threat model assumes that the operating system and application environment are not completely compromised.

Kernel-level malware, hardware keyloggers, fully compromised operating systems and physical attacks are outside the initial scope.

The design will minimize the amount of time that decrypted vault data remains in memory.

