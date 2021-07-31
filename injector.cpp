// injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
using namespace std;

int inject(int pid, char* dllPath)
{
	cout << "Injecting into " << pid << endl;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (addr == NULL) {
		cout << "Error 1" << endl;
		return 0;
	}

	LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == NULL) {
		cout << "Error 2" << endl;
		return 0;
	}

	int n = WriteProcessMemory(process, arg, dllPath, strlen(dllPath), NULL);
	if (n == 0) {
		cout << "Error 3" << endl;
		return 0;
	}

	HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
	if (threadID == NULL) {
		printf("Error 4");
	}

	return 0;
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		cout << "Usage: injector <PID> <DLL Absolute Path>" << endl;
		return 0;
	}

	int pid = atoi(argv[1]);
	inject(pid, argv[2]);
}
