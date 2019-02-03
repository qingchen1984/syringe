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

static void print_banner();
static bool print_process_list();
static bool file_exists(std::string);


int main(int argc, char** argv) {
	
	print_banner();
	
	 // Get the remote target pid
	uint16_t target_pid = get_target_pid();

	if (!target_pid) {
		std::cerr << "Getting remote target process ID failed..." << std::endl;
		return 1;
	}

	// Get the dll's path that we want to inject into our remote target process.
	std::string dll_path = get_dll_path();

	std::cout << "DLL path: " << dll_path << std::endl;

	// Obtain a handle to the target remote process.
	HANDLE target_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

	if (target_process == NULL) {
		std::cerr << "Acquiring a handle to the remote target process failed..." << std::endl;
		return 1;
	}

	// Allocate space for our DLL path inside the target remote process.
	LPVOID dll_path_in_remote_mem_addr = VirtualAllocEx(
		target_process,
		NULL,
		_MAX_PATH,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);

	if (dll_path_in_remote_mem_addr == NULL) {
		std::cerr << "Allocating space for our DLL path in the remote target process's virtual memory space failed..." << std::endl;
		CloseHandle(target_process);
		return 1;
	}

	std::cout << "DLL allocation memory address: " << &dll_path_in_remote_mem_addr << std::endl;

	// Copy the DLL path into the allocated memory region.
	bool write_status = WriteProcessMemory(
		target_process,
		dll_path_in_remote_mem_addr,
		dll_path.c_str(),
		strlen(dll_path.c_str()),
		NULL
	);

	std::cout << "WriteProcessMemory was " << (write_status ? "successful!" : "unsuccessful...") << std::endl;;

	if (!write_status) {
		std::cerr << "GetLastError() for failed WriteProcessMemory() call: " << GetLastError() << std::endl;
		CloseHandle(target_process);
		return 1;
	}

	// Get the address to the LoadLibraryA Windows API function.
	LPVOID load_library_addr = (LPVOID)GetProcAddress(
		GetModuleHandle("kernel32.dll"),
		"LoadLibraryA"
	);

	if (load_library_addr == NULL) {
		std::cerr << "GetProcAddress failed..." << std::endl;
		CloseHandle(target_process);
		return 1;
	}

	std::cout << "LoadLibraryA address: " << &load_library_addr << std::endl;

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

	if (remote_thread == NULL) {
		std::cerr << "CreateRemoteThread failed..." << std::endl;
		return 1;
	}

	std::cout << "Remote thread address: " << &remote_thread << std::endl;

	// Close our remote thread handle and free the allocated memory
	// from the target process our DLL was injected into.
	if (VirtualFreeEx(target_process, dll_path_in_remote_mem_addr, 0, MEM_RELEASE) == 0) {
		std::cerr << "VirtualFreeEx failed on target process..." << std::endl;
	}

	// Free our handle on the remote thread
	CloseHandle(remote_thread);

	// Free our handle on the remote process
	CloseHandle(target_process);

	std::cout << "Press any key to exit..." << std::endl;
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
			std::cerr << "Specified DLL path was invalid, try again..." << std::endl;
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
			std::cerr << "The given process ID is invalid, try again..." << std::endl;
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
	// We don't need to call f.close() since this isn't a dynamic instantiation.
	// As soon as we return out with the return value of f.good(), the object will destruct.
	return f.good();
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
		std::cerr << "EnumProcesses failed..." << std::endl;
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

					printf("%-30s%5s(PID: %u)\n", process_name, " ", processes[i]);
				}
			}
		}
	}

	return true;
}
