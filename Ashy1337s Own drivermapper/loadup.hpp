#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <string>
#include <fstream>
#include <filesystem>
#include <vector>
#include <utility>
#include <cstdlib>
#include <ctime>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NtLoadDriver(PUNICODE_STRING);
extern "C" NTSTATUS NtUnloadDriver(PUNICODE_STRING);

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_PRIVILEGE_NOT_HELD
#define STATUS_PRIVILEGE_NOT_HELD ((NTSTATUS)0xC0000061L)
#endif

namespace driver
{
	namespace util
	{
		inline bool delete_service_entry(const std::string& service_name)
		{
			HKEY reg_handle;
			static const std::string reg_key("System\\CurrentControlSet\\Services\\");

			auto result = RegOpenKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle);
			if (result != ERROR_SUCCESS) return false;

			return ERROR_SUCCESS == RegDeleteKeyA(reg_handle, service_name.data()) &&
				ERROR_SUCCESS == RegCloseKey(reg_handle);
		}

		inline bool create_service_entry(const std::string& drv_path, const std::string& service_name)
		{
			HKEY reg_handle;
			std::string reg_key("System\\CurrentControlSet\\Services\\");
			reg_key += service_name;

			auto result = RegCreateKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle);
			if (result != ERROR_SUCCESS) return false;

			DWORD type_value = 1;
			result = RegSetValueExA(reg_handle, "Type", NULL, REG_DWORD,
				reinterpret_cast<const BYTE*>(&type_value), sizeof(DWORD));
			if (result != ERROR_SUCCESS) { RegCloseKey(reg_handle); return false; }

			DWORD error_control_value = 3;
			result = RegSetValueExA(reg_handle, "ErrorControl", NULL, REG_DWORD,
				reinterpret_cast<const BYTE*>(&error_control_value), sizeof(DWORD));
			if (result != ERROR_SUCCESS) { RegCloseKey(reg_handle); return false; }

			DWORD start_value = 3;
			result = RegSetValueExA(reg_handle, "Start", NULL, REG_DWORD,
				reinterpret_cast<const BYTE*>(&start_value), sizeof(DWORD));
			if (result != ERROR_SUCCESS) { RegCloseKey(reg_handle); return false; }

			result = RegSetValueExA(reg_handle, "ImagePath", NULL, REG_SZ,
				reinterpret_cast<const BYTE*>(drv_path.c_str()), static_cast<DWORD>(drv_path.size() + 1));

			RegCloseKey(reg_handle);
			return result == ERROR_SUCCESS;
		}

		inline bool enable_privilege(const std::wstring& privilege_name)
		{
			HANDLE token_handle = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
				return false;

			LUID luid{};
			if (!LookupPrivilegeValueW(nullptr, privilege_name.data(), &luid))
			{
				CloseHandle(token_handle);
				return false;
			}

			TOKEN_PRIVILEGES token_state{};
			token_state.PrivilegeCount = 1;
			token_state.Privileges[0].Luid = luid;
			token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(token_handle, FALSE, &token_state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
			{
				CloseHandle(token_handle);
				return false;
			}

			CloseHandle(token_handle);
			return true;
		}
	}

	inline NTSTATUS load(const std::string& drv_path, const std::string& service_name)
	{
		if (!util::enable_privilege(L"SeLoadDriverPrivilege"))
			return STATUS_PRIVILEGE_NOT_HELD;

		auto abs_path = std::filesystem::absolute(std::filesystem::path(drv_path)).string();
		if (!util::create_service_entry("\\??\\" + abs_path, service_name))
			return STATUS_UNSUCCESSFUL;

		std::string reg_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
		reg_path += service_name;

		ANSI_STRING driver_rep_path_cstr;
		UNICODE_STRING driver_reg_path_unicode;

		RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
		RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, TRUE);

		NTSTATUS status = NtLoadDriver(&driver_reg_path_unicode);
		RtlFreeUnicodeString(&driver_reg_path_unicode);

		return status;
	}

	inline std::pair<NTSTATUS, std::string> load(const std::vector<std::uint8_t>& drv_buffer)
	{
		auto random_file_name = [](std::size_t length) -> std::string
			{
				std::srand(static_cast<unsigned>(std::time(0)));
				auto randchar = []() -> char
					{
						const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
						const std::size_t max_index = (sizeof(charset) - 2);
						return charset[rand() % max_index];
					};

				std::string str(length, 0);
				std::generate_n(str.begin(), length, randchar);
				return str;
			};

		const auto service_name = random_file_name(16);
		const auto file_path = std::filesystem::temp_directory_path().string() + service_name;

		std::ofstream output_file(file_path.c_str(), std::ios::binary);
		if (!output_file) return { STATUS_UNSUCCESSFUL, "" };

		output_file.write(reinterpret_cast<const char*>(drv_buffer.data()), drv_buffer.size());
		output_file.close();

		return { load(file_path, service_name), service_name };
	}

	inline NTSTATUS unload(const std::string& service_name)
	{
		std::string reg_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
		reg_path += service_name;

		ANSI_STRING driver_rep_path_cstr;
		UNICODE_STRING driver_reg_path_unicode;

		RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
		RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, TRUE);

		NTSTATUS status = NtUnloadDriver(&driver_reg_path_unicode);
		RtlFreeUnicodeString(&driver_reg_path_unicode);

		util::delete_service_entry(service_name);

		try
		{
			std::filesystem::remove(std::filesystem::temp_directory_path().string() + service_name);
		}
		catch (const std::exception&) {}

		return status;
	}
}