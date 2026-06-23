#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <utility>

#ifndef _NTSTATUS_DEFINED
typedef long NTSTATUS;
#define _NTSTATUS_DEFINED
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

class DriverMapper {
public:
    BOOL Init();
    BOOL Shutdown();
    NTSTATUS MapDriver(const std::string& driver_path);
    std::string service_name;

private:
    std::vector<uint8_t> ReadAllBytes(const char* filename);
    std::vector<uint8_t> DownloadVulnerableDriver();
    BOOL DownloadFile(const std::string& url, const std::string& outputPath);
};