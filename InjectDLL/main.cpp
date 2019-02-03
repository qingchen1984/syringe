#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <TlHelp32.h>
#include <tchar.h>
#include <psapi.h>

#define VERSION 0.01

std::string get_dll_path();
uint16_t    get_target_pid();

static void print_error(TCHAR*);
static void print_banner();
static bool print_process_list();
static bool file_exists(std::string);


int main(int argc, char** argv) {
	
	print_banner();
	
	 // Get the remote target pid
	uint16_t target_pid = get_target_pid();

	if (!target_pid) {
		print_error((TCHAR*)"get_target_pid() failed...");
		return 1;
	}

	// Get the dll's path that we want to inject into our remote target process.
	std::string dll_path = get_dll_path();

	// Obtain a handle to the target remote process.
	HANDLE target_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

	// Allocate space for our DLL path inside the target remote process.
	LPVOID dll_path_in_remote_mem_addr = VirtualAllocEx(target_process, NULL, _MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Copy the DLL path into the allocated memory region.
	bool write_status = WriteProcessMemory(
		target_process,
		dll_path_in_remote_mem_addr,
		dll_path.c_str(),
		strlen(dll_path.c_str()),
		NULL
	);

	_tprintf("WriteProcessMemory was %s\n", (write_status ? "successful!" : "unsuccessful..."));

	if (!write_status) {
		_tprintf("GetLastError() for failed WriteProcessMemory() call: %s\n", GetLastError());
	}

	// Get the address to the LoadLibraryA Windows API function.
	LPVOID load_library_addr = (LPVOID)GetProcAddress(
		GetModuleHandle("kernel32.dll"),
		"LoadLibraryA"
	);

	_tprintf("LoadLibraryA address: %p\n", load_library_addr);

	// Create our remote thread for running our DLL code.
	HANDLE remote_thread = CreateRemoteThread(
		target_process,
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)load_library_addr,
		dll_path_in_remote_mem_addr,
		NULL,
		NULL
	);

	_tprintf("Remote thread address: %p\n", &remote_thread);

	WaitForSingleObject(remote_thread, INFINITE);

	// Close our remote thread handle and free the allocated memory
	// from the target process our DLL was injected into.
	DWORD exit_code;
	GetExitCodeThread(remote_thread, &exit_code);
	CloseHandle(remote_thread);
	VirtualFreeEx(target_process, load_library_addr, 0, MEM_RELEASE);

	// Wait for the code execution to finish / terminate.
	_tprintf("Exit code from remote thread: %d\n\nPress any key to terminate...\n", exit_code);

	std::cin.get();

	return 0;
}

std::string get_dll_path() {

	std::string dll_path;
	bool first_input_entered = false;

	do {
		if (first_input_entered) {
			system("cls");
			print_banner();
			std::cout << "Specified DLL path was invalid, try again..." << std::endl;
		}

		std::cout << "Enter path to DLL: ";
		std::getline(std::cin, dll_path);

		if (first_input_entered == false) {
			first_input_entered = true;
		}

		if (dll_path == "exit" ||
			dll_path == "quit") {
			break;
		}

	} while (file_exists(dll_path) == false);

	return dll_path;
}

uint16_t get_target_pid() {
	uint16_t pid = 0;
	
	std::string pid_str;
	bool first_input_entered = false;

	do {
		if (first_input_entered) {
			system("cls");
			print_banner();
			std::cout << "The given process ID is invalid, try again..." << std::endl;
		}

		print_process_list();

		std::cout << "\nEnter target process ID: ";
		std::getline(std::cin, pid_str);

		if (first_input_entered == false) {
			first_input_entered = true;
		}

		if (pid_str == "exit" ||
			pid_str == "quit") {
			break;
		}

	} while (file_exists(pid_str) == false && !pid_str.size());

	if (pid_str != "exit" &&
		pid_str != "quit") {
		pid = (uint16_t)std::stoi(pid_str);
	}

	return pid;
}

static bool file_exists(std::string path) {
	std::ifstream f(path.c_str());
	return f.good();
}

static void print_error(TCHAR* msg) {
	DWORD eNum = GetLastError();
	TCHAR sysMsg[256];
	TCHAR* p;

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	// Display the message
	_tprintf("\n  WARNING: %s failed with error %d (%s)", msg, eNum, sysMsg);
}

static void print_banner() {
	std::cout << "DLL injector v" << VERSION
		<< std::endl
		<< std::endl;
}

static bool print_process_list() {
	DWORD processes[1024];
	DWORD cbNeeded;
	DWORD cProcesses;

	if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
		_tprintf("EnumProcesses failed...");
		return false;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (uint32_t i = 0; i < cProcesses; i++) {
		if (processes[i] != 0) {
			TCHAR process_name[MAX_PATH] = TEXT("<UKNOWN PROCESS>");
			HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

			if (process != NULL) {
				HMODULE hMod;
				cbNeeded = 0;
			
				if (EnumProcessModules(process, &hMod, sizeof(hMod), &cbNeeded)) {
					GetModuleBaseName(process, hMod, process_name, sizeof(process_name) / sizeof(TCHAR));

					_tprintf("%-30s        (PID: %u)\n", process_name, processes[i]);
				}
			}
		}
	}

	return true;
}
