#include "pch.h"
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <iostream>
#include <fstream>

using namespace std;

// Hooking function
// Causing to close the window but not the process itself
void WINAPI hooked_exit(const int status) {
	Sleep(INT_MAX);
}

int PatchIAT()
{
	// Process handle
	HMODULE hModule = GetModuleHandle(NULL);
	
	// Process base address
	LONG baseAddress = (LONG)hModule;

	// DOS Header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	
	// NT Header
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
	
	// Optional Header
	PIMAGE_OPTIONAL_HEADER optionalHeader = (PIMAGE_OPTIONAL_HEADER)&(ntHeader->OptionalHeader);

	// Image Descriptor
	PIMAGE_IMPORT_DESCRIPTOR imageDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Get to msvcrt.dll
	while (imageDescriptor->Characteristics) {
		char* dllName = (char *)(baseAddress + imageDescriptor->Name);

		if (!strcmp("msvcrt.dll", dllName))
			break;

		// Next dll file
		imageDescriptor++;
	}

	// First function
	PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(baseAddress + imageDescriptor->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)((baseAddress + imageDescriptor->FirstThunk));

	// Hook the "exit" and "_exit" functions
	while (!(pFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pFirstThunk->u1.AddressOfData) {
		
		// Each function
		PIMAGE_IMPORT_BY_NAME function = (PIMAGE_IMPORT_BY_NAME)(baseAddress + pFirstThunk->u1.AddressOfData);
		char* funcName = (char *)(function->Name);

		if (!strcmp("exit", funcName) || !strcmp("_exit", funcName))
		{
			// Replacing pointers
			DWORD old = NULL;
			VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), PAGE_READWRITE, &old);
			pFirstThunkTest->u1.Function = (DWORD)hooked_exit;
			VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), old, NULL);
		}

		// Next function
		pFirstThunkTest++;
		pFirstThunk++;
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

	case DLL_THREAD_ATTACH:
		PatchIAT();
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

