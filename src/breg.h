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
DECLSPEC_IMPORT errno_t MSVCRT$strcpy_s(char*, rsize_t, const char*);
DECLSPEC_IMPORT const char* MSVCRT$strrchr(const char*, int);
DECLSPEC_IMPORT errno_t MSVCRT$strncpy_s(char*, size_t, const char*, size_t);
//kernel32 functions
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
//advapi32 functions
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumKeyA(HKEY, DWORD, LPSTR, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegDeleteTreeA(HKEY, LPCSTR);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegConnectRegistryA(LPCSTR, HKEY, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegOpenCurrentUser(REGSAM, PHKEY);

#pragma endregion

typedef enum _REGISTRY_OPERATION{
    RegistryQueryOperation,
    RegistryAddOperation,
    RegistryDeleteOperation
} REGISTRY_OPERATION, *PREGISTRY_OPERATION;

bool ParseArguments(char * args, int arglen, PREGISTRY_OPERATION pRegistryOperation, LPCSTR *lpcRemoteComputerName, HKEY *pHiveRoot, REGSAM *pArchType, LPCSTR *lpcKeyName, LPCSTR *lpcValueName, LPDWORD pdwDataType, LPBYTE *pbData, PLONGLONG pllDataNum, LPDWORD cbData);
HKEY OpenKeyHandle(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, ACCESS_MASK DesiredAccess, LPCSTR KeyName);
void QueryValue(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName, LPCSTR ValueName);
void EnumerateKey(LPCSTR ComputerKey, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName);
void PrintRegistryValue(formatp* pFormatObj, const char* valueName, DWORD dwMaxValueNameLength, DWORD dwRegType, DWORD dataLength, LPBYTE bdata, bool PrintFullBinaryData);
void AddKey(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName);
void AddValue(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName, LPCSTR ValueName, DWORD dwRegType, DWORD dataLength, LPBYTE bdata);
void DeleteKey(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR FullKeyName);
void DeleteValue(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName, LPCSTR ValueName);
const char* HiveRootKeyToString(HKEY HiveRoot);
const char* DataTypeToString(DWORD regType);
const char* ArchTypeToString(REGSAM ArchType);

