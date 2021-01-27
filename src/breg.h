#include <windows.h>
#include <stdbool.h>
#include "beacon.h"

#pragma instrinsic(memcpy,strcpy,strcmp,strlen)
#pragma region WINAPI_IMPORTS

#define MAX_DATATYPE_STRING_LENGTH 13   //REG_EXPAND_SZ

//msvcrt functions
DECLSPEC_IMPORT int MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT int MSVCRT$atoi(const char*);
DECLSPEC_IMPORT LONGLONG MSVCRT$_atoi64(const char*);
//kernel32 functions
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
//advapi32 functions
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegOpenKeyA(HKEY, LPCSTR, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumKeyA(HKEY, DWORD, LPSTR, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);


#pragma endregion

typedef enum _REGISTRY_OPERATION{
    RegistryQueryOperation,
    RegistryAddOperation,
    RegistryDeleteOperation
} REGISTRY_OPERATION, *PREGISTRY_OPERATION;

bool ParseArguments(char * args, int arglen, PREGISTRY_OPERATION pRegistryOperation, LPCSTR *lpcRemoteComputerName, HKEY *pHiveRoot, LPCSTR *lpcKeyName, LPCSTR *lpcValueName, LPDWORD pdwDataType, LPBYTE *pbData, PLONGLONG pllDataNum, LPDWORD cbData);
void QueryKey(LPCSTR ComputerName, HKEY HiveRoot, LPCSTR KeyName, LPCSTR ValueName);
void EnumerateKey(LPCSTR ComputerKey, HKEY HiveRoot, LPCSTR KeyName);
const char* HiveRootKeyToString(HKEY HiveRoot);
const char* DataTypeToString(DWORD regType);
