#include <Windows.h>
#include <iostream>
#include "color.h"
#include <WindowsDefender.h>
#include <fstream>
#include <thread>
#include <chrono>
#include <intrin.h>
#include <tchar.h>
#pragma warning(disable : 4996)

bool is_admin()
{
	HANDLE token;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
	{
		TOKEN_ELEVATION elevation{};
		DWORD size;

		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &size))
			return elevation.TokenIsElevated;
	}
	return false;
}

BOOL __stdcall stop_dependent_services(const SC_HANDLE& schSCManager, const SC_HANDLE& schService)
{
	DWORD bytes_needed;
	DWORD count;

	LPENUM_SERVICE_STATUS dependencies = nullptr;
	SERVICE_STATUS_PROCESS ssp{};

	const DWORD start_time = GetTickCount();

	// Pass a zero-length buffer to get the required buffer size.
	if (EnumDependentServices(schService, SERVICE_ACTIVE,
	                          dependencies, 0, &bytes_needed, &count))
	{
		// If the Enum call succeeds, then there are no dependent
		// services, so do nothing.
		return TRUE;
	}

	if (GetLastError() != ERROR_MORE_DATA)
		return FALSE; // Unexpected error

	// Allocate a buffer for the dependencies.
	dependencies = static_cast<LPENUM_SERVICE_STATUS>(HeapAlloc(
		GetProcessHeap(), HEAP_ZERO_MEMORY, bytes_needed));

	if (!dependencies)
		return FALSE;

	__try
	{
		// Enumerate the dependencies.
		if (!EnumDependentServices(schService, SERVICE_ACTIVE,
		                           dependencies, bytes_needed, &bytes_needed,
		                           &count))
			return FALSE;

		for (DWORD i = 0; i < count; i++)
		{
			const ENUM_SERVICE_STATUS ess = *(dependencies + i);
			// Open the service.
			const SC_HANDLE dep_service = OpenService(schSCManager,
			                                          ess.lpServiceName,
			                                          SERVICE_STOP | SERVICE_QUERY_STATUS);

			if (!dep_service)
				return FALSE;

			__try
			{
				// Send a stop code.
				if (!ControlService(dep_service,
				                    SERVICE_CONTROL_STOP,
				                    reinterpret_cast<LPSERVICE_STATUS>(&ssp)))
					return FALSE;

				// Wait for the service to stop.
				while (ssp.dwCurrentState != SERVICE_STOPPED)
				{
					Sleep(ssp.dwWaitHint);
					if (!QueryServiceStatusEx(
						dep_service,
						SC_STATUS_PROCESS_INFO,
						reinterpret_cast<LPBYTE>(&ssp),
						sizeof(SERVICE_STATUS_PROCESS),
						&bytes_needed))
						return FALSE;

					if (ssp.dwCurrentState == SERVICE_STOPPED)
						break;
					constexpr DWORD timeout = 30000;
					if (GetTickCount() - start_time > timeout)
						return FALSE;
				}
			}
			__finally
			{
				// Always release the service handle
				CloseServiceHandle(dep_service);
			}
		}
	}
	__finally
	{
		// Always free the enumeration buffer
		HeapFree(GetProcessHeap(), 0, dependencies);
	}
	return TRUE;
}

bool enable_or_disable_service(const char* strServiceName, bool bIsEnable)
{
	bool result = false;

	const SC_HANDLE hServiceControlManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);

	if (nullptr != hServiceControlManager)
	{
		const SC_HANDLE hService = OpenService(hServiceControlManager, strServiceName, SERVICE_CHANGE_CONFIG);

		if (hService != nullptr)
		{
			result = ChangeServiceConfig(hService, SERVICE_NO_CHANGE,
			                             bIsEnable ? SERVICE_AUTO_START : SERVICE_DISABLED,
			                             SERVICE_NO_CHANGE,
			                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

			CloseServiceHandle(hService);
		}

		CloseServiceHandle(hServiceControlManager);
	}

	return result;
}

VOID __stdcall do_stop_svc(const char* szSvcName)
{
	SERVICE_STATUS_PROCESS ssp{};
	const DWORD start_time = GetTickCount();
	DWORD bytes_needed;
	constexpr DWORD dw_timeout = 30000; // 30-second time-out

	const SC_HANDLE sch_sc_manager = OpenSCManager(
		nullptr, // local computer
		nullptr, // ServicesActive database 
		SC_MANAGER_ALL_ACCESS); // full access rights 

	if (nullptr == sch_sc_manager)
	{
		std::cout << color::red("[-] OpenSCManager failed ") << GetLastError() << std::endl;
		return;
	}

	// Get a handle to the service
	const SC_HANDLE sch_service = OpenService(
		sch_sc_manager, // SCM database 
		szSvcName, // name of service 
		SERVICE_STOP |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	if (sch_service == nullptr)
	{
		std::cout << color::red("[-] OpenService failed ") << GetLastError() << std::endl;
		CloseServiceHandle(sch_sc_manager);
		return;
	}

	// Make sure the service is not already stopped
	if (!QueryServiceStatusEx(
		sch_service,
		SC_STATUS_PROCESS_INFO,
		reinterpret_cast<LPBYTE>(&ssp),
		sizeof(SERVICE_STATUS_PROCESS),
		&bytes_needed))
	{
		std::cout << color::red("[-] QueryServiceStatusEx failed ") << GetLastError() << std::endl;
		goto stop_cleanup;
	}

	if (ssp.dwCurrentState == SERVICE_STOPPED)
	{
		std::cout << color::red("[!] Service is already stopped\n");
		goto stop_cleanup;
	}

	// If a stop is pending, wait for it
	while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
	{
		std::cout << color::green("[+] Service stop pending...\n");

		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth of the wait hint but not less than 1 second  
		// and not more than 10 seconds.
		DWORD wait_time = ssp.dwWaitHint / 10;

		if (wait_time < 1000)
			wait_time = 1000;
		else if (wait_time > 10000)
			wait_time = 10000;

		Sleep(wait_time);

		if (!QueryServiceStatusEx(
			sch_service,
			SC_STATUS_PROCESS_INFO,
			reinterpret_cast<LPBYTE>(&ssp),
			sizeof(SERVICE_STATUS_PROCESS),
			&bytes_needed))
		{
			std::cout << color::red("[-] QueryServiceStatusEx failed ") << GetLastError() << std::endl;
			goto stop_cleanup;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
		{
			std::cout << color::green("[+] Service stopped successfully\n");
			goto stop_cleanup;
		}

		if (GetTickCount() - start_time > dw_timeout)
		{
			std::cout << color::red("[!] Service stop timed out\n");
			goto stop_cleanup;
		}
	}

	// If the service is running, dependencies must be stopped first
	stop_dependent_services(sch_sc_manager, sch_service);

	// Send a stop code to the service
	if (!ControlService(
		sch_service,
		SERVICE_CONTROL_STOP,
		reinterpret_cast<LPSERVICE_STATUS>(&ssp)))
	{
		std::cout << color::red("[-] ControlService failed ") << GetLastError() << std::endl;
		goto stop_cleanup;
	}

	while (ssp.dwCurrentState != SERVICE_STOPPED)
	{
		Sleep(ssp.dwWaitHint);
		if (!QueryServiceStatusEx(
			sch_service,
			SC_STATUS_PROCESS_INFO,
			reinterpret_cast<LPBYTE>(&ssp),
			sizeof(SERVICE_STATUS_PROCESS),
			&bytes_needed))
		{
			std::cout << color::red("[-] QueryServiceStatusEx failed ") << GetLastError() << std::endl;
			goto stop_cleanup;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
			break;

		if (GetTickCount() - start_time > dw_timeout)
		{
			std::cout << color::red("[!] Wait timed out\n");
			goto stop_cleanup;
		}
	}
	std::cout << szSvcName << color::green(" service stopped successfully\n");

stop_cleanup:
	CloseServiceHandle(sch_service);
	CloseServiceHandle(sch_sc_manager);
}

void features()
{
	do
	{
		std::cout << " \n";
		std::cout << color::yellow("Write the number of the function you want to turn off\n");
		std::cout << color::yellow(
			" 1 - Clean up temp windows files\n 2 - Clean up temp app files\n 3 - Remove 100% hardware usage\n 4 - Remove windows defender and hidden system monitoring\n 5 - Remove windows store\n 6 - Clean up chrome cookie files\n 7 - Remove windows updates\n 8 - Enable seconds in clock\n 9 - Fix for accessing administrative rules\n 10 - System info\n 11 - System file checker (SFC)\n 12 - Evaluate register based ban risk\n");
		int var;
		std::cin >> var;

		switch (var)
		{
		case 1:
			{
				SHFILEOPSTRUCT file_op{};

				file_op.hwnd = nullptr;
				file_op.wFunc = FO_DELETE;
				file_op.pFrom = R"(C:\Windows\Temp\)";
				file_op.pTo = nullptr;
				file_op.fFlags = 0;
				file_op.lpszProgressTitle = nullptr;

				SHFileOperation(&file_op);
				GetLastError()
					? std::cout << color::red("[-] Temp files removed not successfully\n")
					: std::cout << color::green("[+] Temp files removed successfully\n");
			}
			break;
		case 2:
			{
				system("del /s /f /q %temp%\\*.*");
				GetLastError()
					? std::cout << color::red("[-] Temp files removed not successfully\n")
					: std::cout << color::green("[+] Temp files removed successfully\n");
			}
			break;
		case 3:
			{
				//system("sc config SysMain start= disabled");

				do_stop_svc("SysMain");
				enable_or_disable_service("SysMain", false);
				std::cout << color::red("Plz, reboot your pc !!!\n");
			}
			break;
		case 4:
			{
				HKEY key;
				if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, R"(SOFTWARE\Policies\Microsoft\Windows Defender)", 0,
				                 KEY_ALL_ACCESS, &key))
				{
					std::cout << color::red("[-] Failed to open registry\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] Register opened successfully\n");

				uint32_t payload = 1;
				if (RegSetValueEx(key, "DisableAntiSpyware", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'DisableAntiSpyware'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'DisableAntiSpyware\' value changed to 1\n");

				HKEY new_key;
				if (RegCreateKeyEx(key, "Real-Time Protection", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
				                   nullptr, &new_key, nullptr))
				{
					std::cout << color::red("[-] Failed to create new key \'Real-Time Protection'\\n");
					system("pause");
					return;
				}
				std::cout << color::green("[+] New key \'Real-Time Protection\' created successfully\n");

				key = new_key;

				if (RegSetValueEx(key, "DisableRealtimeMonitoring", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to registry\n");
					system("pause");
					return;
				}
				std::cout << color::green("[+] The reg key \'DisableRealtimeMonitoring\' value changed to 1\n");

				if (RegSetValueEx(key, "DisableBehaviorMonitoring", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to registry\n");
					system("pause");
					return;
				}
				std::cout << color::green("[+] The reg key \'DisableBehaviorMonitoring\' value changed to 1\n");

				if (RegSetValueEx(key, "DisableOnAccessProtection", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to registry\n");
					system("pause");
					return;
				}
				std::cout << color::green("[+] The reg key \'DisableOnAccessProtection\' value changed to 1\n");

				if (RegSetValueEx(key, "DisableScanOnRealtimeEnable", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to registry\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'DisableScanOnRealtimeEnable\' value changed to 1\n");

				if (RegSetValueEx(key, "DisableIOAVProtection", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to registry\n");
					system("pause");
					return;
				}
				std::cout << color::green("[+] The reg key \'DisableIOAVProtection\' value changed to 1\n");

				RegCloseKey(key);

				std::cout << color::green("[+] Registry values written\n");

				//DoStopSvc(("mpssvc"));
				//EnableOrDisableService(("mpssvc"), false);

				//DoStopSvc(("wscsvc"));
				//EnableOrDisableService(("wscsvc"), false);

				std::cout << color::red("[!] Plz, reboot your pc \n");
			}
			break;
		case 5:
			{
				do_stop_svc("InstallService");
				enable_or_disable_service("InstallService", false);
				std::cout << color::red("Plz, reboot your pc !!!\n");
			}
			break;
		case 6:
			{
				system(R"(del /s /f /q %appdata%\Local\Google\Chrome\User Data\Default\Cookies)");

				GetLastError()
					? std::cout << color::red("[-] Cookies cleaned not successfully\n")
					: std::cout << color::green("[+] Cookies cleaned removed successfully\n");
			}
			break;
		case 7:
			{
				do_stop_svc("wuauserv");
				enable_or_disable_service("wuauserv", false);

				do_stop_svc("msiserver");
				enable_or_disable_service("msiserver", false);

				system(R"(del /s /f /q C:\Windows\SoftwareDistribution\*.*)");
				std::cout << color::green("Deleted windows updates\n");

				std::ofstream file(R"(C:\Windows\SoftwareDistribution\Download)");
				file.close();
				std::cout << color::green("Created Download file\n");
			}
			break;
		case 8:
			{
				HKEY key;
				if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft", 0,
				                 KEY_ALL_ACCESS, &key))
				{
					std::cout << color::red("[-] Failed to open registry\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] Register opened successfully\n");

				HKEY new_key;

				if (RegCreateKeyEx(key, "Windows", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
				                   nullptr, &new_key, nullptr))
				{
					std::cout << color::red("[-] Failed to create new key \'Windows'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] New key \'Windows\' created successfully\n");
				key = new_key;

				if (RegCreateKeyEx(key, "CurrentVersion", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
				                   nullptr, &new_key, nullptr))
				{
					std::cout << color::red("[-] Failed to create new key \'CurrentVersion'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] New key \'CurrentVersion\' created successfully\n");
				key = new_key;

				if (RegCreateKeyEx(key, "Explorer", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
				                   nullptr, &new_key, nullptr))
				{
					std::cout << color::red("[-] Failed to create new key \'Explorer'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] New key \'Explorer\' created successfully\n");
				key = new_key;

				if (RegCreateKeyEx(key, "Advanced", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
				                   nullptr, &new_key, nullptr))
				{
					std::cout << color::red("[-] Failed to create new key \'Advanced'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] New key \'Advanced\' created successfully\n");
				key = new_key;

				uint32_t payload = 1;
				if (RegSetValueEx(key, "ShowSecondsInSystemClock", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'ShowSecondsInSystemClock'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'ShowSecondsInSystemClock\' value changed to 1\n");

				/* std::cout << color::red(("[+] Updating explorer..."));
				system(("taskkill /F /IM explorer.exe"));
				std::this_thread::sleep_for(std::chrono::seconds(3));
				system(("start explorer")); */

				std::cout << color::red("[!] Restart explorer\n");
			}
			break;
		case 9:
			{
				HKEY key;
				if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System)",
				                 0,
				                 KEY_ALL_ACCESS, &key))
				{
					std::cout << color::red("[-] Failed to open registry\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] Register opened successfully\n");

				uint32_t payload = 0;
				if (RegSetValueEx(key, "FilterAdministratorToken", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'FilterAdministratorToken'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'FilterAdministratorToken\' value changed to 0\n");

				if (RegSetValueEx(key, "PromptOnSecureDesktop", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'PromptOnSecureDesktop'\\n");
					system("pause");
					return;
				}

				if (RegSetValueEx(key, "EnableInstallerDetection", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'EnableInstallerDetection'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'EnableInstallerDetection\' value changed to 0\n");

				if (RegSetValueEx(key, "EnableSecureUIAPaths", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'EnableSecureUIAPaths'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'EnableSecureUIAPaths\' value changed to 0\n");

				if (RegSetValueEx(key, "EnableVirtualization", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'EnableVirtualization'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'EnableVirtualization\' value changed to 0\n");

				if (RegSetValueEx(key, "EnableUIADesktopToggle", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'EnableUIADesktopToggle'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'EnableUIADesktopToggle\' value changed to 0\n");

				if (RegSetValueEx(key, "EnableLUA", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'EnableLUA'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'EnableLUA\' value changed to 0\n");
				uintptr_t logon = 1;
				if (RegSetValueEx(key, "undockwithoutlogon", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&logon),
				                  sizeof logon))
				{
					std::cout << color::red("[-] Failed to write to reg key \'undockwithoutlogon'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'undockwithoutlogon\' value changed to 1\n");

				if (RegSetValueEx(key, "shutdownwithoutlogon", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&logon),
				                  sizeof logon))
				{
					std::cout << color::red("[-] Failed to write to reg key \'shutdownwithoutlogon'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'shutdownwithoutlogon\' value changed to 1\n");

				if (RegSetValueEx(key, "scforceoption", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'scforceoption'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'scforceoption\' value changed to 0\n");

				if (RegSetValueEx(key, "legalnoticetext", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'legalnoticetext'\\n");
					system("pause");
					return;
				}

				//std::cout << color::green(("[+] The reg key \'legalnoticetext\' value changed to 0\n"));

				//if (RegSetValueEx(key, ("legalnoticecaption"), 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				//	sizeof(payload)))
				//{
				//	std::cout << color::red(("[-] Failed to write to reg key \'legalnoticecaption'\\n"));
				//	system(("pause"));
				//	return;
				//}

				//std::cout << color::green(("[+] The reg key \'legalnoticecaption\' value changed to 0\n"));

				//if (RegSetValueEx(key, ("dontdisplaylastusername"), 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				//	sizeof(payload)))
				//{
				//	std::cout << color::red(("[-] Failed to write to reg key \'dontdisplaylastusername'\\n"));
				//	system(("pause"));
				//	return;
				//}

				//std::cout << color::green(("[+] The reg key \'dontdisplaylastusername\' value changed to 0\n"));

				if (RegSetValueEx(key, "ValidateAdminCodeSignatures", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'ValidateAdminCodeSignatures'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'ValidateAdminCodeSignatures\' value changed to 0\n");

				uintptr_t curs = 1;
				if (RegSetValueEx(key, "EnableCursorSuppression", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&curs),
				                  sizeof curs))
				{
					std::cout << color::red("[-] Failed to write to reg key \'EnableCursorSuppression'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'EnableCursorSuppression\' value changed to 1\n");

				uintptr_t dsc = 2;
				if (RegSetValueEx(key, "DSCAutomationHostEnabled", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&dsc),
				                  sizeof dsc))
				{
					std::cout << color::red("[-] Failed to write to reg key \'DSCAutomationHostEnabled'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'DSCAutomationHostEnabled\' value changed to 2\n");

				uintptr_t beusr = 3;
				if (RegSetValueEx(key, "ConsentPromptBehaviorUser", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&beusr),
				                  sizeof beusr))
				{
					std::cout << color::red("[-] Failed to write to reg key \'ConsentPromptBehaviorUser'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'ConsentPromptBehaviorUser\' value changed to 3\n");

				if (RegSetValueEx(key, "ConsentPromptBehaviorAdmin", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&payload),
				                  sizeof payload))
				{
					std::cout << color::red("[-] Failed to write to reg key \'ConsentPromptBehaviorAdmin'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'ConsentPromptBehaviorAdmin\' value changed to 0\n");

				HKEY new_key;

				if (RegOpenKeyEx(
					HKEY_LOCAL_MACHINE,
					R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI\Clipboard\ExceptionFormats)",
					0,
					KEY_ALL_ACCESS, &new_key))
				{
					std::cout << color::red("[-] Failed to create new key \'Windows'\\n");
					system("pause");
					return;
				}

				key = new_key;
				std::cout << color::green("[+] Register opened successfully\n");

				uint32_t bitmap = 2;

				if (RegSetValueEx(key, "CF_BITMAP", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&bitmap),
				                  sizeof bitmap))
				{
					std::cout << color::red("[-] Failed to write to reg key \'CF_BITMAP'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'CF_BITMAP\' value changed to 2\n");

				uint32_t dib = 8;

				if (RegSetValueEx(key, "CF_DIB", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&dib),
				                  sizeof dib))
				{
					std::cout << color::red("[-] Failed to write to reg key \'CF_DIB'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'CF_DIB\' value changed to 8\n");

				uint32_t dib5 = 17;

				if (RegSetValueEx(key, "CF_DIBV5", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&dib5),
				                  sizeof dib5))
				{
					std::cout << color::red("[-] Failed to write to reg key \'CF_DIBV5'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'CF_DIBV5\' value changed to 17\n");

				uint32_t oemtext = 7;

				if (RegSetValueEx(key, "CF_OEMTEXT", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&oemtext),
				                  sizeof oemtext))
				{
					std::cout << color::red("[-] Failed to write to reg key \'CF_OEMTEXT'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'CF_OEMTEXT\' value changed to 7\n");

				uint32_t palette = 9;

				if (RegSetValueEx(key, "CF_PALETTE", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&palette),
				                  sizeof palette))
				{
					std::cout << color::red("[-] Failed to write to reg key \'CF_PALETTE'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'CF_PALETTE\' value changed to 9\n");

				uint32_t text = 1;

				if (RegSetValueEx(key, "CF_TEXT", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&palette),
				                  sizeof palette))
				{
					std::cout << color::red("[-] Failed to write to reg key \'CF_TEXT'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'CF_TEXT\' value changed to 1\n");

				uint32_t textu = 13;

				if (RegSetValueEx(key, "CF_UNICODETEXT", 0, REG_DWORD, reinterpret_cast<LPBYTE>(&textu),
				                  sizeof textu))
				{
					std::cout << color::red("[-] Failed to write to reg key \'CF_UNICODETEXT'\\n");
					system("pause");
					return;
				}

				std::cout << color::green("[+] The reg key \'CF_UNICODETEXT\' value changed to 13\n");
				std::cout << color::red("[!] Plz, reboot your pc \n");
			}
			break;
		case 10:
			{
				MEMORYSTATUSEX statex{};
				statex.dwLength = sizeof statex;
				GlobalMemoryStatusEx(&statex);

				std::cout << color::green("System Info:\n");
				std::cout << color::red(
					"-----------------------------------------MEM---------------------------------------\n");
				{
					std::cout << color::green("Memory in use: ") << statex.dwMemoryLoad << "%\n";
					std::cout << color::green("Total MB of physical memory: ") << statex.ullTotalPhys / 1024 / 1024 <<
						std::endl;
					std::cout << color::green("Free MB of physical memory: ") << statex.ullAvailPhys / 1024 / 1024 <<
						std::endl;
				}
				std::cout << color::red(
					"-----------------------------------------CPU---------------------------------------\n");
				{
					SYSTEM_INFO lpSystemInfo;
					GetSystemInfo(&lpSystemInfo);
					std::cout << color::green("Active processor mask: ") << lpSystemInfo.dwActiveProcessorMask <<
						std::endl;
					std::cout << color::green("Number of processors: ") << lpSystemInfo.dwNumberOfProcessors <<
						std::endl;
					std::cout << color::green("Processor type: ") << lpSystemInfo.dwProcessorType << std::endl;

					DWORD buffer_size = _MAX_PATH;
					DWORD dwMHz = _MAX_PATH;
					HKEY hkey;

					// open the key where the proc speed is hidden:
					long error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
					                          R"(HARDWARE\DESCRIPTION\System\CentralProcessor\0)",
					                          0,
					                          KEY_READ,
					                          &hkey);

					if (error != ERROR_SUCCESS)
					{
						wchar_t constexpr buffer[260]{};

						FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
						              nullptr,
						              error,
						              0,
						              (CHAR*)buffer,
						              _MAX_PATH,
						              nullptr);
						wprintf(buffer);
						system("pause");
						return;
					}

					RegQueryValueEx(hkey, "~MHz", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwMHz), &buffer_size);
					std::cout << color::green("CPU speed: ") << dwMHz << "Mhz\n";
				}
				std::cout << color::red(
					"-----------------------------------------VC---------------------------------------\n");
				{
					for (int i = 0; ; i++)
					{
						DISPLAY_DEVICE dd = {sizeof dd, {0}};
						BOOL f = EnumDisplayDevices(nullptr, i, &dd, EDD_GET_DEVICE_INTERFACE_NAME);
						if (!f)
							break;

						std::cout << color::green(dd.DeviceString) << std::endl;
					}
				}
				std::cout << color::red(
					"-----------------------------------------WIN---------------------------------------\n");
				{
					DWORD version = 0;
					DWORD major_version = 0;
					DWORD minor_version = 0;
					DWORD build = 0;

					version = GetVersion();

					major_version = static_cast<DWORD>(LOBYTE(LOWORD(version)));
					minor_version = static_cast<DWORD>(HIBYTE(LOWORD(version)));

					if (version < 0x80000000)
						build = static_cast<DWORD>(HIWORD(version));

					std::cout << color::green("Version is ") << major_version << "." << minor_version << " " << build <<
						std::endl;
				}
			}
			break;
		case 11:
		{
			/* @TODO: Working only on x64 solution platform */
			system("sfc.exe /scannow");

			/* lol */
			//if (GetLastError())
			//	system(R"(C:\Windows\System32\sfc.exe /scannow)");
		} break;
		case 12:
		{
			/* evaluates reg */
			std::cout << color::green("Analyzing Registry...") << std::endl;

			char selection = ' ';

			HKEY reg_key;
			LSTATUS status = 0;
			status = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Hex-Rays\\IDA\\History64", 0, KEY_ALL_ACCESS, &reg_key);
			if (status == ERROR_SUCCESS)
			{
				DWORD values = 0;
				if (ERROR_SUCCESS == (RegQueryInfoKeyA(reg_key, NULL, NULL, NULL, NULL, NULL, NULL, &values, NULL, NULL, NULL, NULL)))
				{
					std::cout << color::light_yellow("[IDA] Found ") << values << color::light_yellow(" potentially risky value(s).") << std::endl;
					if (values > 0)
					{
						std::cout << color::light_yellow("[IDA] Analyzing value(s)...") << std::endl;

						//checking strings for suspicious names
						std::string sus_names[] = { "modern", "warfare", "black", "ops", "call", "duty", "cod", "mw", "bocw", "war", "cold", "dump" };
						size_t found = 0;
						TCHAR data[MAX_PATH];
						DWORD dwSize = sizeof(data);
						for (unsigned int i = 0; i < values; i++)
						{
							status = RegGetValueA(reg_key, NULL, std::to_string(i).c_str(), RRF_RT_REG_SZ, NULL, &data, &dwSize);
							if (status == ERROR_SUCCESS)
							{
								std::string str = data;
								for (int j = 0; j < sizeof(sus_names); j++)
								{
									found = str.find(sus_names[i]);
									if (found != str.npos)
									{
										if (ERROR_SUCCESS != (RegDeleteValueA(reg_key, std::to_string(i).c_str())))
											std::cout << color::red("[IDA] Could not delete dangerous element. Error: ") << GetLastError() << std::endl;
										else {
											std::cout << color::green("[IDA] Deleted Element ") << i << color::green(" - found ") << sus_names[j] << color::green(" inside of data: ") << str << std::endl;
											break;
										}
									}
								}
							}
							else
								std::cout << color::red("[IDA] Error: ") << GetLastError() << color::red(" while trying to obtain data of value ") << i << std::endl;
						}

						std::cout << color::green("[IDA] Key values analyzed. Moderate Risk caused by IDA keys inside of current users registry.") << std::endl;
					}
				}
				else
					std::cout << color::red("Unable to get key info! Extended Error Information: ") << GetLastError() << std::endl;
				RegCloseKey(reg_key);
			}
			else
			{
				if (GetLastError() != 0x0)	//do not display an error if the key doesn't even exist.
					std::cout << color::red("Can not open registry key. Error Information: ") << GetLastError() << std::endl;
			}
			status = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Hex-Rays\\IDA\\History\\UIFLTR", 0, KEY_ALL_ACCESS, &reg_key);
			if (status == ERROR_SUCCESS)
			{
				DWORD values = 0;
				if (ERROR_SUCCESS == (RegQueryInfoKeyA(reg_key, NULL, NULL, NULL, NULL, NULL, NULL, &values, NULL, NULL, NULL, NULL)))
				{
					std::cout << color::light_yellow("[IDA] Found ") << values << color::light_yellow(" search histories.") << std::endl;
					if (values > 0) 
					{
						std::cout << color::light_yellow("[IDA] Cleanup search histories? [y/n]\n >");
						std::cin >> selection;
						if (selection == 'y')
						{
							for (unsigned int i = 0; i < values; i++)
							{
								status = RegDeleteValueA(reg_key, std::to_string(i).c_str());
								if (status == ERROR_SUCCESS)
									std::cout << color::green("[IDA] Element ") << i << color::green(" deleted!") << std::endl;
								else
									std::cout << color::red("[IDA] Error: ") << GetLastError() << color::red(" while trying to delete ") << i << std::endl;
							}
						}
					}
				}
				else
					std::cout << color::red("[IDA] Unable to get key info! Extended Error Information: ") << GetLastError() << std::endl;
				RegCloseKey(reg_key);
			}
			else
			{
				if (GetLastError() != 0x0)
					std::cout << color::red("[IDA] Can not open registry key. Error Information: ") << GetLastError() << std::endl;
			}

			std::cout << color::green("===Done!===") << std::endl;
			
		} break;	
		default: break;
		}
	}
	while (FindWindow(nullptr, "pc-cleaner"));
}

int main()
{
	if (!is_admin())
	{
		std::cout << color::red("[-] Run the program as admin\n");
		system("pause");
		return 0;
	}

	SetConsoleTitleA("pc-cleaner");

	std::cout << " \n";
	std::cout << color::aqua(
		"Hello, World!\n developer contacts:\n @tg: https://t.me/kernel_mode2\n @ds: william_coder#8276\n @github: https://github.com/W1lliam1337\n");

	features();

	return 0;
}
