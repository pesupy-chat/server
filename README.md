# pesupy-chat

The project aims to create an end-to-end encrypted chat platform that enables users to securely exchange text messages. It consists of a Server program, which runs on a network-connected computer, and a command-line Client application for users to connect, create accounts, and engage in secure chatting with other account holders on the server.

### Server Program

The Server is a socket server that accepts packets from the Client, performing various operations as requested, including account creation, login, and message transmission. Users interested in hosting their own server can execute this on their computer.

### Client Application

The Client program is a command-line interface that provides end-users with a straightforward experience. Upon execution, it displays a Sign Up/Login screen where users can create new accounts or log in to existing ones. Post-login, users can seamlessly communicate with others who have accounts on the server.

### Security Measures

Client messages are securely transmitted using end-to-end encryption, ensuring data confidentiality between the Client, Server, and recipients. Account credentials are also transported securely using the same encryption method to prevent unauthorized access to user accounts. Additionally, account credentials and chat backups are stored in an encrypted format within the Server's MySQL database, providing an extra layer of security.

## Explanation &amp; Installation

### End-to-End Encryption

End-to-end encryption (E2EE) is a robust data encryption method that ensures only the sender and intended recipient can access the data. This is achieved through a pair of mathematically linked keys: a public key used for encryption and a private key used for decryption. E2EE ensures privacy and security by never storing private keys on third-party servers, preventing even service providers from decrypting messages.

### Server Setup

The server setup process involves the following steps:

1. Selection of a folder for server operation files.
2. Creation of MySQL schemas and tables.
3. Generation of an encryption keypair for secure traffic.
4. Password creation for server access protection.
5. Configuration of the network port for incoming connections.

Once set up, the server listens for connections, enabling users to sign up, log in, and send and receive messages.

### Key Pair Usage

To enhance security, this project employs an additional layer of end-to-end encryption, as it does not utilize SSL/TLS due to port restrictions and certificate complexities. This ensures absolute security during data transmission.

### Account Creation

Users can execute the Client program to connect to a hosted server. The account creation process involves entering basic information, such as full name, email (optional), username, and password. The server securely stores this data in its MySQL database and generates a chat encryption keypair for each user.

### Initiating a Chat

Once logged in, users access the main interface, where they can see their chats and start new conversations. They can enter the username of the person they want to chat with and engage in secure messaging. The Client uses SQLite for local data storage.

## Future Enhancements

The project's future enhancements may include:

- Development of a GUI-based Client for user-friendliness.
- Mobile platform Clients (e.g., Android).
- Support for formatted text and various message types (voice, image, video).
- Group chat and file sharing features with end-to-end encryption.
- Cross-server messaging for increased flexibility and security.

This open-source project empowers users to control their chat server's security and functionality while providing a user-friendly experience.

_README.md created by [Si6gma](https://github.com/Si6gma)_
