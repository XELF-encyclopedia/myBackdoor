#include <iostream>
#include <winsock2.h>
#include <string>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib") // Link with the ws2_32.lib library
std::string firstWord(std::string sentence)
{
    size_t spacePos = sentence.find(' ');
    std::string firstWord;
    if (spacePos != std::string::npos) {
        firstWord = sentence.substr(0, spacePos);
    }
    else {
        firstWord = sentence;
    }
    return firstWord;
}
int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket." << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Listen on any available network interface
    serverAddr.sin_port = htons(4444); // Use port 4444

    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed." << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed." << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server listening on port 4444..." << std::endl;

    sockaddr_in clientAddr;
    int clientAddrSize = sizeof(clientAddr);
    SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Accept failed." << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    int clientPort = ntohs(clientAddr.sin_port);

    std::cout << "Client connected." << std::endl;
    std::cout << "Client IP: " << clientIP << std::endl;
    std::cout << "Client Port: " << clientPort << std::endl;

    // ============================================================================
    // MODIFICATION: Loop to send multiple messages until user types "Quit"
    // ============================================================================
    while (true) {
        std::string message;
        std::cout << "\nEnter a message to send to the client (type 'Quit' to exit): ";
        std::getline(std::cin, message);

        // Send the size of the message first, so the client knows how much to receive
        int messageSize = message.length();
        int networkSize = htonl(messageSize); // Convert to network byte order

        if (send(clientSocket, (char*)&networkSize, sizeof(int), 0) == SOCKET_ERROR) {
            std::cerr << "Send size failed. Client may have disconnected." << std::endl;
            break; // Exit loop on error
        }

        // Send the actual message
        int totalSent = 0;
        while (totalSent < messageSize) {
            int sent = send(clientSocket, message.c_str() + totalSent, messageSize - totalSent, 0);
            if (sent == SOCKET_ERROR) {
                std::cerr << "Send failed. Client may have disconnected." << std::endl;
                break;
            }
            totalSent += sent;
        }

        if (totalSent < messageSize) {
            break; // Exit if send was incomplete
        }

        std::cout << "Message sent successfully." << std::endl;

        // Check if user wants to quit
        if (message == "Quit") {
            std::cout << "Quit command sent. Closing connection..." << std::endl;
            break; // Exit the loop
        }
        if (message == "ls"||firstWord(message)=="shell")
        {
            //pending working
            int networkSize=0;
            int bytesReceived = recv(clientSocket, (char*)&networkSize, sizeof(int), 0);
            if (bytesReceived <= 0) {
                std::cerr << "Connection closed by server or failed to receive message size." << std::endl;
                break;
            }

            int messageSize = ntohl(networkSize);

            // Validate message size to prevent excessive allocation
            if (messageSize <= 0 || messageSize > 1048576) { // Max 1MB
                std::cerr << "Invalid message size: " << messageSize << std::endl;
                break;
            }

            // Receive the actual message
            char* buffer = new char[messageSize + 1];
            memset(buffer, 0, messageSize + 1);

            int totalReceived = 0;
            while (totalReceived < messageSize) {
                bytesReceived = recv(clientSocket, buffer + totalReceived, messageSize - totalReceived, 0);
                if (bytesReceived <= 0) {
                    std::cerr << "Failed to receive message data." << std::endl;
                    delete[] buffer;
                    closesocket(clientSocket);
                    WSACleanup();
                    return 1;
                }
                totalReceived += bytesReceived;
            }

            std::string receivedMessage(buffer);
            std::cout << "\nReceived message:\n " << receivedMessage << std::endl;
        }

    }
    // ============================================================================
    // END MODIFICATION
    // ============================================================================

    closesocket(clientSocket);
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}