#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <time.h>
#include <string>
#include <stdio.h>
#include <conio.h>

using namespace std;

HMODULE InjectDll(DWORD ProcessId, const char* dllPath);
BOOL EnableDebugPrivileges();
DWORD GetProcessIdFromName(const char* processName);
DWORD FreeDll(DWORD processId, HMODULE dll);
HMODULE GetRemoteModuleBase(char* moduleName, DWORD processId);
std::string GetMyExecutableFullFilename();

DWORD processId;

int main( int argc, const char* argv[] )
{
	const char* processName;
	std::string dllPath;

	if (argc < 3) {
		printf("Usage: %s <full_filename_exe> <dll_to_inject>\n", argv[0]);
		_getch();
		return -1;
	}

	processName = argv[1];
	dllPath = argv[2];
	
	if (dllPath.find_last_of('\\') == std::string::npos) {
		std::string myExePath = GetMyExecutableFullFilename();
		myExePath = myExePath.substr(0, myExePath.find_last_of('\\'));
		dllPath = myExePath + "\\" + dllPath;
	}

	if (!EnableDebugPrivileges()){
		printf("Failed to get debug privileges.\n");
		_getch();
		return 0;
	}

	//Get process id
	printf("Waiting process %s...\n", processName);
	while ((processId = GetProcessIdFromName(processName)) == 0)
	{
		printf(".");
		Sleep(5000);
	}
	printf("Process %s found, slepping for 10 seconds for process full loading...\n", processName);
	Sleep(10000);

	processId = GetProcessIdFromName(processName);
	if (processId == 0){
		printf("Failed to get %s process id.\n", processName);
		_getch();
		return -1;
	}
	printf("Process id = %d ( %x )\n", processId, processId);

	//Inject the dll
	printf("Injecting %s into %s.\n", dllPath.c_str(), processName);
	HMODULE dllBase = InjectDll(processId, dllPath.c_str());
	
	if (dllBase == 0){
		TerminateProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId), 0);
		printf("Failed to inject %s! You probably need a new version!\n", dllPath.c_str());
		_getch();
		return -4;
	}

	printf("Successfully injected %s, base address: %08p.\n", dllPath.c_str(), dllBase);
	//FreeDll(processId,dllBase);
	//_getch();
	return 0;
}

HMODULE GetRemoteModuleBase(char* moduleName, DWORD processId)
{
	HANDLE snapshot;
	HMODULE moduleBase = 0;

	if (processId == 0) 
		return 0;


	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

	if (snapshot != NULL)
	{
		BOOL moduleExists;
		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(MODULEENTRY32); 

		//Loop throught all modules in the target process
		moduleExists = Module32First(snapshot, &moduleEntry);
		while (moduleExists)
		{
			//Store module base and break if target found
			if (_stricmp(moduleEntry.szModule, moduleName) == 0)
			{
				moduleBase = (HMODULE)moduleEntry.modBaseAddr;
				break;
			}

			//Get next module in process
			moduleExists = Module32Next(snapshot, &moduleEntry);		
		}

		CloseHandle(snapshot); 
	}

	return moduleBase;
}

#if defined(_WIN64) || defined(IS64BIT)

const char RemoteInjectFunc[] = "\x48\x83\xEC\x28\x48\xB9\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xD0\x48\x83\xC4\x28\x48\xA3\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC3";;
// 00470000 - 48 83 EC 28            - sub rsp,28 { 40 }
// 004C0000 - 48 B9 FFFFFFFFFFFFFFFF - mov rcx,FFFFFFFFFFFFFFFF { -1 }
// 004C0016 - 48 B8 FFFFFFFFFFFFFFFF - mov rax,FFFFFFFFFFFFFFFF { -1 }
// 004C0020 - FF D0                  - call rax
// 004C0028 - 48 83 C4 28            - add rsp,28 { 40 }
// 004C0022 - 48 A3 FFFFFFFFFFFFFFFF - mov [FFFFFFFFFFFFFFFF],rax { -1 }
// 004C002C - C3                     - ret 


HMODULE InjectDll(DWORD ProcessId, const char* dllPath)
{
	UCHAR code[sizeof(RemoteInjectFunc)];
	HMODULE injectedDllBase = 0;
	HANDLE processHandle;
	SIZE_T bytesIO;
	void* remotePathAddress;
	void* remoteThreadFuncAddress = NULL;
	void* remoteResult = NULL;

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (processHandle == NULL)
		return FALSE;

	size_t dllPathLength = strlen(dllPath) + 1;

	//Alocate memory of the dll path size in the remote process 
	//and store the address where dllPath will be written to in remotePathAddress
	remotePathAddress = VirtualAllocEx(processHandle, NULL, dllPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remotePathAddress) {
		printf("Cant inject dll %s: alloc memory 'for path' error %d\n", dllPath, GetLastError());
		return NULL;
	}
	//Write the dll path to the allocated memory
	WriteProcessMemory(processHandle, remotePathAddress, dllPath, dllPathLength, &bytesIO);

	remoteResult = VirtualAllocEx(processHandle, NULL, 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remoteResult) {
		printf("Cant inject dll %s: alloc memory 'for result' error %d\n", dllPath, GetLastError());
		return NULL;
	}

	memcpy(&code[0],&RemoteInjectFunc[0],sizeof(RemoteInjectFunc));
	*(uintptr_t*)&code[6] = (uintptr_t)remotePathAddress;
#pragma push_macro("LoadLibraryA")
#undef LoadLibraryA
	*(uintptr_t*)&code[16] = (uintptr_t)&LoadLibraryA;
#pragma pop_macro("LoadLibraryA")
	*(uintptr_t*)&code[32] = (uintptr_t)remoteResult;

	remoteThreadFuncAddress = VirtualAllocEx(processHandle, NULL, sizeof(RemoteInjectFunc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteThreadFuncAddress) {
		printf("Cant inject dll %s: alloc memory 'func' error %d\n", dllPath, GetLastError());
		return NULL;
	}
	WriteProcessMemory(processHandle, remoteThreadFuncAddress, &code, sizeof(RemoteInjectFunc), &bytesIO);
	if (bytesIO != 0)
	{
		HANDLE remoteThreadHandle;

		//Create a thread in the remote process that starts at the LoadLibrary function,
		//and passes in the dllPath string as the argument, making the remote process call LoadLibrary on our dll
		remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteThreadFuncAddress, NULL, 0, NULL);
		if (!remoteThreadHandle) {
			printf("Cant create thread, error %d\n", GetLastError());
		}

		//Wait for LoadLibrary in the remote process to finish then store the thread exit code
		//which will be the return value of LoadLibrary, the module handle
		WaitForSingleObject(remoteThreadHandle, INFINITE);
		//GetExitCodeThread(remoteThreadHandle, &injectedDllBase);	
		ReadProcessMemory(processHandle, remoteResult, &injectedDllBase, sizeof(uintptr_t), &bytesIO);
		CloseHandle(remoteThreadHandle);
	}

	//Free the allocated memory
	VirtualFreeEx(processHandle, remotePathAddress, 0, MEM_RELEASE);
	VirtualFreeEx(processHandle, remoteThreadFuncAddress, 0, MEM_RELEASE);
	VirtualFreeEx(processHandle, remoteResult, 0, MEM_RELEASE);
	return injectedDllBase;
}

#else

HMODULE InjectDll(DWORD ProcessId, const char* dllPath)
{
	HMODULE injectedDllBase = 0;
	HMODULE kernel32Handle;
	HMODULE kernel32HandleRemote;
	HANDLE processHandle = startedProcess.hProcess;

	//Get the address of the LoadLibraryA function in kernel32.dll
	kernel32Handle = GetModuleHandle("kernel32.dll");

	kernel32HandleRemote = (HMODULE)GetRemoteModuleBase("kernel32.dll", startedProcess.dwProcessId);
	printf("kernel handle local = %x,  remote = %x\n", kernel32Handle, kernel32HandleRemote);
	if (kernel32Handle != NULL)
	{
		FARPROC loadLibrary;
		loadLibrary = GetProcAddress(kernel32Handle, "LoadLibraryA");
		if (loadLibrary != NULL)
		{
			SIZE_T bytesWritten;
			void* remotePathAddress;
			void* remoteCodeAddress;
			unsigned int dllPathLength = dllPath.length() + 1;

			//Alocate memory of the dll path size in the remote process 
			//and store the address where dllPath will be written to in remotePathAddress
			remotePathAddress = VirtualAllocEx(processHandle, NULL, dllPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			//Write the dll path to the allocated memory
			WriteProcessMemory(processHandle, remotePathAddress, dllPath.c_str(), dllPathLength, &bytesWritten);

			if (bytesWritten != 0)
			{
				HANDLE remoteThreadHandle;

				//Create a thread in the remote process that starts at the LoadLibrary function,
				//and passes in the dllPath string as the argument, making the remote process call LoadLibrary on our dll
				remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, 
					(LPTHREAD_START_ROUTINE)loadLibrary, remotePathAddress, 0, NULL);
				//remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, 
					//(LPTHREAD_START_ROUTINE)remoteCodeAddress, NULL, 0, NULL);

				//Wait for LoadLibrary in the remote process to finish then store the thread exit code
				//which will be the return value of LoadLibrary, the module handle
				WaitForSingleObject(remoteThreadHandle, INFINITE);
				GetExitCodeThread(remoteThreadHandle, (LPDWORD)&injectedDllBase);	

				CloseHandle(remoteThreadHandle);
			}

			//Free the allocated memory
			VirtualFreeEx(processHandle, remotePathAddress, 0, MEM_RELEASE);
		}

		CloseHandle(kernel32Handle);
	}

	CloseHandle(processHandle);

	return injectedDllBase;
}

#endif

BOOL EnableDebugPrivileges()
{
	BOOL success = FALSE;
	HANDLE tokenHandle;
	LUID luid;
	TOKEN_PRIVILEGES newPrivileges;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tokenHandle))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			newPrivileges.PrivilegeCount = 1;
			newPrivileges.Privileges[0].Luid = luid;
			newPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (AdjustTokenPrivileges(tokenHandle, FALSE, &newPrivileges, sizeof(newPrivileges), NULL, NULL))
				success = TRUE;
		}

		CloseHandle(tokenHandle);
	}

	return success;
}

DWORD GetProcessIdFromName(const char* processName)
{
	HANDLE snapshot;
	DWORD processId = 0;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != NULL)
	{
		PROCESSENTRY32 processEntry;
		BOOL processExists;

		processEntry.dwSize = sizeof(PROCESSENTRY32);

		//Loop through all processes in the snapshot until target is found or no more processes
		processExists = Process32First(snapshot, &processEntry);
		while (processExists)
		{
			//Store process id and break if process name is the target name
			if (_stricmp(processEntry.szExeFile, processName) == 0)
			{
				processId = processEntry.th32ProcessID;
				break;
			}

			//Get next process in snapshot
			processExists = Process32Next(snapshot, &processEntry);		
		}

		CloseHandle(snapshot);
	}

	return processId;
}

DWORD FreeDll(DWORD processId, HMODULE dll)
{
	HMODULE kernel32Handle;
	HANDLE processHandle;
	DWORD retcode;
	//Get access to the process
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (processHandle == NULL)
		return FALSE;
			 
	//Get the address of the LoadLibraryA function in kernel32.dll
	kernel32Handle = GetModuleHandle("kernel32.dll");
	if (kernel32Handle != NULL)	{
		FARPROC freeLibrary;
		freeLibrary = GetProcAddress(kernel32Handle, "FreeLibrary");
		if (freeLibrary != NULL){
			HANDLE remoteThreadHandle;

			remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, 
				(LPTHREAD_START_ROUTINE)freeLibrary, (void*)dll, 0, NULL);

			WaitForSingleObject(remoteThreadHandle, INFINITE);
			GetExitCodeThread(remoteThreadHandle, &retcode);	

			CloseHandle(remoteThreadHandle);
		}

	//	CloseHandle(kernel32Handle);
	}

	CloseHandle(processHandle);

	return retcode;
}

std::string GetMyExecutableFullFilename()
{
	char buffer[500];
	GetModuleFileName(NULL, buffer, sizeof(buffer));
	return buffer;
}
