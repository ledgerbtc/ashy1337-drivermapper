// main.cpp - Drag & Drop Driver Mapping
#include <iostream>
#include <string>
#include <Windows.h>
#include <filesystem>
#include <winternl.h>
#include "DriverMapper.hpp"

#pragma comment(lib, "comdlg32.lib")

namespace fs = std::filesystem;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

void PrintBanner() {
    system("cls");
    std::cout << R"(
 /$$$$$$$           /$$                     /$$                        
| $$__  $$         | $$                    |__/                        
| $$  \ $$ /$$$$$$ | $$  /$$$$$$  /$$$$$$$  /$$ /$$   /$$ /$$$$$$/$$$$ 
| $$$$$$$//$$__  $$| $$ /$$__  $$| $$__  $$| $$| $$  | $$| $$_  $$_  $$
| $$____/| $$  \ $$| $$| $$  \ $$| $$  \ $$| $$| $$  | $$| $$ \ $$ \ $$
| $$     | $$  | $$| $$| $$  | $$| $$  | $$| $$| $$  | $$| $$ | $$ | $$
| $$     |  $$$$$$/| $$|  $$$$$$/| $$  | $$| $$|  $$$$$$/| $$ | $$ | $$
|__/      \______/ |__/ \______/ |__/  |__/|__/ \______/ |__/ |__/ |__/
                                                                       
                                                                       
                                                                       
)" << "\n";
    std::cout << "    Driver Mapper Using | Lenovo Diagnostics Exploit\n";
    std::cout << "\n\n";
}

bool MapDriverFile(const std::string& driverPath) {
    if (!fs::exists(driverPath)) {
        std::cout << "[-] File not found: " << driverPath << "\n";
        return false;
    }

    // Verify it's a .sys file
    if (fs::path(driverPath).extension().string() != ".sys") {
        std::cout << "[-] File must be a .sys driver file\n";
        return false;
    }

    std::cout << "\n[*] Target: " << fs::path(driverPath).filename().string() << "\n";
    std::cout << "[*] File path: " << driverPath << "\n";
    std::cout << "[*] Initializing Driver Mapper...\n";

    DriverMapper mapper;

    if (!mapper.Init()) {
        std::cout << "[-] Failed to initialize! Make sure you run as Administrator.\n";
        return false;
    }

    std::cout << "[+] Vulnerable driver loaded: " << mapper.service_name << "\n";
    std::cout << "[*] Mapping driver into kernel memory...\n";

    NTSTATUS status = mapper.MapDriver(driverPath);

    if (NT_SUCCESS(status)) {
        std::cout << "[+] SUCCESS! Driver mapped. Return: 0x" << std::hex << status << "\n";
    }
    else {
        std::cout << "[-] FAILED! NTSTATUS: 0x" << std::hex << status << "\n";
    }

    std::cout << "[*] Cleaning up vulnerable driver...\n";
    mapper.Shutdown();

    return NT_SUCCESS(status);
}

int main(int argc, char* argv[]) {
    PrintBanner();

    // Check if driver file was provided (drag & drop)
    if (argc < 2) {
        std::cout << "[-] No driver file specified!\n\n";
        std::cout << "[*] Usage: Drag and drop a .sys driver file onto this executable\n";
        std::cout << "[*] Or run from command line: DriverMapper.exe <driver_path>\n\n";
        std::cout << "[*] Press any key to exit...";
        system("pause >nul");
        return 1;
    }

    std::string targetDriver = argv[1];

    // Check if file exists before proceeding
    if (!fs::exists(targetDriver)) {
        std::cout << "[-] File not found: " << targetDriver << "\n";
        std::cout << "\n[*] Press any key to exit...";
        system("pause >nul");
        return 1;
    }

    // Map the provided driver
    bool success = MapDriverFile(targetDriver);

    std::cout << "\n[*] Press any key to exit...";
    system("pause >nul");
    return success ? 0 : 1;
}