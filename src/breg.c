

#include "breg.h"

void go(char* args, int arglen){

    REGISTRY_OPERATION registryOperation;
    LPCSTR ComputerName;
    HKEY HiveRoot;
    REGSAM ArchType;
    LPCSTR KeyName;
    LPCSTR ValueName;
    DWORD DataType;
    LPBYTE Data;
    LONGLONG DataNum;
    DWORD DataSize;
    
    if(!ParseArguments(args, arglen, &registryOperation, &ComputerName, &HiveRoot, &ArchType, &KeyName, &ValueName, &DataType, &Data, &DataNum, &DataSize))
        return;

    if(registryOperation == RegistryQueryOperation){
        if(ValueName == NULL)
            EnumerateKey(ComputerName, HiveRoot, ArchType, KeyName);
        else
            QueryValue(ComputerName, HiveRoot, ArchType, KeyName, ValueName);;
    }
    else if (registryOperation == RegistryAddOperation){
        if(ValueName == NULL)
            AddKey(ComputerName, HiveRoot, ArchType, KeyName);
        else
            AddValue(ComputerName, HiveRoot, ArchType, KeyName, ValueName, DataType, DataSize, Data);
    }
    else if (registryOperation == RegistryDeleteOperation){
        if(ValueName == NULL)
            DeleteKey(ComputerName, HiveRoot, ArchType, KeyName);
        else
            DeleteValue(ComputerName, HiveRoot, ArchType, KeyName, ValueName);
    }

}

void DeleteKey(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR FullKeyName){

    if(FullKeyName == NULL || strlen(FullKeyName) == 0){
        BeaconPrintf(CALLBACK_ERROR, "breg: Cannot add root hive as key\n");
        return;
    }

    bool deleteFromRoot = false;
    DWORD lastSlashOffset = 0;
    const char* lastSlash = MSVCRT$strrchr((const char*) FullKeyName, '\\');

    if(lastSlash == NULL)
        deleteFromRoot = true;
    else{
        lastSlashOffset = (DWORD)(lastSlash - FullKeyName);
        if(lastSlashOffset == strlen(FullKeyName) - 1){
            BeaconPrintf(CALLBACK_ERROR, "breg: The specified key cannot end in '\\'\n");
            return;
        }
    }

    //registry keys cannot be more than 255 chars
    char ParentKeyName[256];
    char ChildKeyName[256];
    if(deleteFromRoot){
        ParentKeyName[0] = 0;
        MSVCRT$strncpy_s(ChildKeyName, 256, FullKeyName, strlen(FullKeyName));
    }
    else{
        MSVCRT$strncpy_s(ParentKeyName, 256, FullKeyName, lastSlashOffset);
        MSVCRT$strncpy_s(ChildKeyName, 256, lastSlash + 1, strlen(FullKeyName) - lastSlashOffset - 1);
    }

    HKEY hParentKey = OpenKeyHandle(ComputerName, HiveRoot, ArchType, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, ParentKeyName);

    if(hParentKey == NULL)
        return;

    const char* hiveRootString = HiveRootKeyToString(HiveRoot);
    const char* rootSeparator = (strlen(FullKeyName) == 0) ? "" : "\\";
    const char* archString = ArchTypeToString(ArchType);
    const char* computerString = ComputerName == NULL ? "" : ComputerName;
    const char* computerNameSeparator = ComputerName == NULL ? "" : "\\";

    LSTATUS lret = ADVAPI32$RegDeleteTreeA(hParentKey, ChildKeyName);

    ADVAPI32$RegCloseKey(hParentKey);

    if(lret != ERROR_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to delete key '%s%s%s%s%s' %s [error %d]\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, FullKeyName, archString, lret);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n Deleted key '%s%s%s%s%s' %s\n\nDONE\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, FullKeyName, archString);

}

void DeleteValue(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName, LPCSTR ValueName){

    const char* hiveRootString = HiveRootKeyToString(HiveRoot);
    const char* rootSeparator = (strlen(KeyName) == 0) ? "" : "\\";
    const char* archString = ArchTypeToString(ArchType);
    const char* computerString = ComputerName == NULL ? "" : ComputerName;
    const char* computerNameSeparator = ComputerName == NULL ? "" : "\\";

    HKEY hKey = OpenKeyHandle(ComputerName, HiveRoot, ArchType, KEY_SET_VALUE , KeyName);
    if(hKey == NULL)
        return;

    LSTATUS lret = ADVAPI32$RegDeleteValueA(hKey, ValueName);

    ADVAPI32$RegCloseKey(hKey);

    if(lret != ERROR_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to delete value '%s' from '%s%s%s%s%s' %s [error %d]\n", ValueName, computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString, lret);
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n Deleted value '%s' from '%s%s%s%s%s' %s\n\nDONE\n", ValueName, computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString);

}

void AddKey(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName){

    const char* hiveRootString = HiveRootKeyToString(HiveRoot);
    const char* rootSeparator = (strlen(KeyName) == 0) ? "" : "\\";
    const char* archString = ArchTypeToString(ArchType);
    const char* computerString = ComputerName == NULL ? "" : ComputerName;
    const char* computerNameSeparator = ComputerName == NULL ? "" : "\\";

    HKEY hHiveRoot = OpenKeyHandle(ComputerName, HiveRoot, ArchType, KEY_CREATE_SUB_KEY, NULL);
    if(hHiveRoot == NULL)
        return;

    HKEY hNewKey;
    DWORD dwDisposition;
    LSTATUS lret = ADVAPI32$RegCreateKeyExA(hHiveRoot, KeyName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hNewKey, &dwDisposition);

    if(hHiveRoot != HiveRoot)   //we have to close it properly if it's a handle to a remote computer
        ADVAPI32$RegCloseKey(hHiveRoot);

    if(lret != ERROR_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "breg: failed to create key '%s%s%s%s%s' %s [error %d]", computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString, lret);
        return;
    }

    ADVAPI32$RegCloseKey(hNewKey);

    if(dwDisposition == REG_OPENED_EXISTING_KEY){
        BeaconPrintf(CALLBACK_ERROR, "breg: The key '%s%s%s%s%s' %s already exists\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n Created key '%s%s%s%s%s' %s\n\nDONE\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString);

}

void AddValue(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName, LPCSTR ValueName, DWORD dwRegType, DWORD dataLength, LPBYTE bdata){

    const char* hiveRootString = HiveRootKeyToString(HiveRoot);
    const char* rootSeparator = (strlen(KeyName) == 0) ? "" : "\\";
    const char* archString = ArchTypeToString(ArchType);
    const char* computerString = ComputerName == NULL ? "" : ComputerName;
    const char* computerNameSeparator = ComputerName == NULL ? "" : "\\";

    HKEY hKey = OpenKeyHandle(ComputerName, HiveRoot, ArchType, KEY_QUERY_VALUE | KEY_SET_VALUE, KeyName);
    if(hKey == NULL)
        return;

    LSTATUS lret = ADVAPI32$RegQueryValueExA(hKey, ValueName, NULL, NULL, NULL, NULL);

    const char* successOperationString = (lret == ERROR_SUCCESS) ? "Overwrote" : "Added";
    const char* failOperationString = (lret == ERROR_SUCCESS) ? "overwrite" : "add";
    const char* preposition = (lret == ERROR_SUCCESS) ? "in" : "to";

    lret = ADVAPI32$RegSetValueExA(hKey, ValueName, 0, dwRegType, bdata, dataLength);

    ADVAPI32$RegCloseKey(hKey);

    if(lret != ERROR_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to %s value '%s' %s '%s%s%s%s%s' %s [error %d]\n", failOperationString, ValueName, preposition, computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString, lret);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n %s value '%s' %s '%s%s%s%s%s' %s\n\nDONE\n", successOperationString, ValueName, preposition, computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString);

}

//returns a handle to the specified registry key, null if failure
HKEY OpenKeyHandle(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, ACCESS_MASK DesiredAccess, LPCSTR KeyName){
    
    LSTATUS lret;
    HKEY hKey = NULL;

    const char* hiveRootString = HiveRootKeyToString(HiveRoot);

    const char* computerString = ComputerName;
    const char* computerNameSeparator = "\\";
    if(ComputerName == NULL)
        computerNameSeparator = computerString = "";

    if(ComputerName != NULL){
        HKEY hRemoteRoot;
        lret = ADVAPI32$RegConnectRegistryA(ComputerName, HiveRoot, &hRemoteRoot);
        if(lret != ERROR_SUCCESS){
            BeaconPrintf(CALLBACK_ERROR, "breg: Failed to connect to '%s%s%s' [error %d]\n", computerString, computerNameSeparator, hiveRootString, lret);
            return NULL;
        }
        lret = ADVAPI32$RegOpenKeyExA(hRemoteRoot, KeyName, 0, ArchType | DesiredAccess, &hKey);
        ADVAPI32$RegCloseKey(hRemoteRoot);
        if(lret != ERROR_SUCCESS){
            BeaconPrintf(CALLBACK_ERROR, "breg: Connection succeeded but failed to open key '%s%s%s\\%s' [error %d]\n", computerString, computerNameSeparator, hiveRootString, KeyName, lret);
            return NULL;
        }
    }
    else{
        if(HiveRoot != HKEY_CURRENT_USER)
            lret = ADVAPI32$RegOpenKeyExA(HiveRoot, KeyName, 0, ArchType | DesiredAccess, &hKey);
        else{
            HKEY hCurrentUserRoot;
            lret = ADVAPI32$RegOpenCurrentUser(ArchType | DesiredAccess, &hCurrentUserRoot);
            if(lret != ERROR_SUCCESS){
                BeaconPrintf(CALLBACK_ERROR, "breg: Opening of HKCU of current user failed [error %d]\n", lret);
                return NULL;
            }
            lret = ADVAPI32$RegOpenKeyExA(hCurrentUserRoot, KeyName, 0, ArchType | DesiredAccess, &hKey);
            ADVAPI32$RegCloseKey(hCurrentUserRoot);
        }
        if(lret != ERROR_SUCCESS){
            BeaconPrintf(CALLBACK_ERROR, "breg: Failed to open '%s%s%s\\%s' [error %d]\n", computerString, computerNameSeparator, hiveRootString, KeyName, lret);
            return NULL;
        }
    }

    return hKey;
}

void QueryValue(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName, LPCSTR ValueName){

    HANDLE hHeap = KERNEL32$GetProcessHeap();

    if(hHeap == NULL){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to open process heap [error %d]\n", KERNEL32$GetLastError());
        return;
    }

    LSTATUS lret;
    HKEY hKey = OpenKeyHandle(ComputerName, HiveRoot, ArchType, KEY_READ, KeyName);
    if(hKey == NULL)
        return;

    const char* hiveRootString = HiveRootKeyToString(HiveRoot);

    DWORD dwType;
    DWORD dwDataLength = 0;
    LPBYTE bdata = NULL;
    lret = ADVAPI32$RegQueryValueExA(hKey, ValueName, NULL, &dwType, NULL, &dwDataLength);

    const char* rootSeparator = (strlen(KeyName) == 0) ? "" : "\\";
    const char* archString = ArchTypeToString(ArchType);
    const char* computerString = ComputerName == NULL ? "" : ComputerName;
    const char* computerNameSeparator = ComputerName == NULL ? "" : "\\";

    if(lret != ERROR_SUCCESS && lret!= ERROR_MORE_DATA){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to query value '%s' in key '%s%s%s%s%s' [error %d]\n", ValueName, computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, lret);
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    bdata = (LPBYTE)KERNEL32$HeapAlloc(hHeap, 0, dwDataLength);
    if(bdata == NULL){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to allocate %d bytes from process heap [error %d]\n", dwDataLength, KERNEL32$GetLastError());
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    lret = ADVAPI32$RegQueryValueExA(hKey, ValueName, NULL, &dwType, bdata, &dwDataLength);
    if(lret != ERROR_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to query value '%s' in key '%s%s%s%s%s' [error %d]\n", ValueName, computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, lret);
        KERNEL32$HeapFree(hHeap, 0, (LPVOID)bdata);
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    formatp fpOutputAlloc;
    DWORD rowSize = 2 + strlen(ValueName) + 4 + MAX_DATATYPE_STRING_LENGTH + 4 + dwDataLength + 2;
    BeaconFormatAlloc(&fpOutputAlloc, 512 + (rowSize * 3));

    BeaconFormatPrintf(&fpOutputAlloc, "\n[%s%s%s%s%s] %s\n\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString);

    const char* valString = strlen(ValueName) == 0 ? "(default)" : ValueName;

    BeaconFormatPrintf(&fpOutputAlloc, "  %s    %*s%s    %*s%s\n", "Name", strlen(valString) - 4, "", "Type", MAX_DATATYPE_STRING_LENGTH - 4, "", "Data");
    BeaconFormatPrintf(&fpOutputAlloc, "  %s    %*s%s    %*s%s\n", "----", strlen(valString) - 4, "", "----", MAX_DATATYPE_STRING_LENGTH - 4, "", "----");

    PrintRegistryValue(&fpOutputAlloc, valString, strlen(valString), dwType, dwDataLength, bdata, true);
    
    BeaconFormatPrintf(&fpOutputAlloc, "\nDONE\n");

    int iOutputLength;  
    char* beaconOutputString = BeaconFormatToString(&fpOutputAlloc, &iOutputLength);
    BeaconOutput(CALLBACK_OUTPUT, beaconOutputString, iOutputLength + 1);
    
    KERNEL32$HeapFree(hHeap, 0, (LPVOID)bdata);
    BeaconFormatFree(&fpOutputAlloc);
    ADVAPI32$RegCloseKey(hKey);

}

void EnumerateKey(LPCSTR ComputerName, HKEY HiveRoot, REGSAM ArchType, LPCSTR KeyName){    

    HANDLE hHeap = KERNEL32$GetProcessHeap();

    if(hHeap == NULL){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to open process heap [error %d]\n", KERNEL32$GetLastError());
        return;
    }

    LSTATUS lret;
    HKEY hKey = OpenKeyHandle(ComputerName, HiveRoot, ArchType, KEY_READ, KeyName);
    if(hKey == NULL)
        return;

    const char* hiveRootString = HiveRootKeyToString(HiveRoot);

    DWORD dwNumSubkeys;
    DWORD dwMaxSubkeyNameLength;
    DWORD dwNumValues;
    DWORD dwMaxValueNameLength;
    DWORD dwMaxDataLength;

    lret = ADVAPI32$RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwNumSubkeys, &dwMaxSubkeyNameLength, NULL, &dwNumValues, &dwMaxValueNameLength, &dwMaxDataLength, NULL, NULL);

    if(lret != ERROR_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "breg: Failed to query information of '%s\\%s' [error %d]\n", hiveRootString, KeyName, lret);
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    if(dwMaxValueNameLength < 9)
        dwMaxValueNameLength = 9;   //"(default)" has length 9
    if(dwMaxDataLength < 32)
        dwMaxDataLength = 32;   //to account for display binary data if it exists

    //2 spaces + len(hiveroot) + '\' + keyname + '\' + subkey + '\n;
    DWORD dwFullSubkeyNameMaxSize = 2 + 4 + 1 + strlen(KeyName) + 1 + dwMaxSubkeyNameLength + 1;
    if(dwFullSubkeyNameMaxSize < 24)
        dwFullSubkeyNameMaxSize = 24; //max length of error string (with some padding)

    //2 spaces + len(valuename) + 4 spaces + max(typelen) + 4 spaces + len(data) + '\n'
    DWORD dwFullValueLength = 2 + dwMaxValueNameLength + 4 + 9 + 4 + dwMaxDataLength + 1;
    if(dwFullValueLength < 24)
        dwFullValueLength = 24; //max length of error string (with some padding)

    int outputLength = 512 + (dwFullSubkeyNameMaxSize * dwNumSubkeys) + (dwFullValueLength * (dwNumValues + 2));

    formatp fpOutputAlloc;
    BeaconFormatAlloc(&fpOutputAlloc, outputLength);

    const char* rootSeparator = (strlen(KeyName) == 0) ? "" : "\\";
    const char* archString = ArchTypeToString(ArchType);
    const char* computerString = ComputerName;
    const char* computerNameSeparator = "\\";
    if(ComputerName == NULL)
        computerNameSeparator = computerString = "";

    BeaconFormatPrintf(&fpOutputAlloc, "\n[%s%s%s%s%s] %s\n\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, KeyName, archString);

    //first enumerate the subkeys
    if(dwNumSubkeys == 0){
        BeaconFormatPrintf(&fpOutputAlloc, "[No Subkeys]\n");
    }
    else{

        LPSTR subkeyName = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, dwMaxSubkeyNameLength + 1);

        if(subkeyName == NULL){
            BeaconPrintf(CALLBACK_ERROR, "breg: Failed to allocate %d bytes memory from process heap [error %d]\n", dwMaxSubkeyNameLength + 1, KERNEL32$GetLastError());
            ADVAPI32$RegCloseKey(hKey);
            BeaconFormatFree(&fpOutputAlloc);
            return;
        }

        BeaconFormatPrintf(&fpOutputAlloc, "Subkeys [%d]:\n\n", dwNumSubkeys);

        for(int i = 0; i < dwNumSubkeys; i++){
            lret = ADVAPI32$RegEnumKeyA(hKey, i, subkeyName, dwMaxSubkeyNameLength + 1);
            if(lret != ERROR_SUCCESS){
                BeaconFormatPrintf(&fpOutputAlloc, "  [error %d]\n", lret);
                continue;
            }
            BeaconFormatPrintf(&fpOutputAlloc, "  %s%s%s\\%s\n", hiveRootString, rootSeparator, KeyName, subkeyName);
        }

        KERNEL32$HeapFree(hHeap, 0, (LPVOID)subkeyName);

    }

    //now enumerate values
    if(dwNumValues == 0){
        BeaconFormatPrintf(&fpOutputAlloc, "\n[No Values]\n");
    }
    else{
        LPSTR valueName = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, dwMaxValueNameLength + 1);
        if(valueName == NULL){
            BeaconPrintf(CALLBACK_ERROR, "breg: Failed to allocate %d bytes memory from process heap [error %d]\n", dwMaxValueNameLength + 1, KERNEL32$GetLastError());
            ADVAPI32$RegCloseKey(hKey);
            BeaconFormatFree(&fpOutputAlloc);
            return;
        }

        LPBYTE bdata = (LPBYTE)KERNEL32$HeapAlloc(hHeap, 0, dwMaxDataLength);
        if(bdata == NULL){
            BeaconPrintf(CALLBACK_ERROR, "breg: Failed to allocate %d bytes memory from process heap [error %d]\n", dwMaxDataLength, KERNEL32$GetLastError());
            KERNEL32$HeapFree(hHeap, 0, (LPVOID)valueName);
            ADVAPI32$RegCloseKey(hKey);
            BeaconFormatFree(&fpOutputAlloc);
            return;
        }

        BeaconFormatPrintf(&fpOutputAlloc, "\nValues [%d]:\n\n", dwNumValues);

        BeaconFormatPrintf(&fpOutputAlloc, "  %s    %*s%s    %*s%s\n", "Name", dwMaxValueNameLength - 4, "", "Type", MAX_DATATYPE_STRING_LENGTH - 4, "", "Data");
        BeaconFormatPrintf(&fpOutputAlloc, "  %s    %*s%s    %*s%s\n", "----", dwMaxValueNameLength - 4, "", "----", MAX_DATATYPE_STRING_LENGTH - 4, "", "----");
        for(int i = 0; i < dwNumValues; i++){
            DWORD valueNameLength = dwMaxValueNameLength + 1;
            DWORD dataLength = dwMaxDataLength;
            DWORD dwRegType;
            lret = ADVAPI32$RegEnumValueA(hKey, i, valueName, &valueNameLength, NULL, &dwRegType, bdata, &dataLength);
            if(lret != ERROR_SUCCESS){
                BeaconFormatPrintf(&fpOutputAlloc, "  [error %d]\n", lret);
                continue;
            }
            if(strlen(valueName) == 0)
                MSVCRT$strcpy_s(valueName, dwMaxValueNameLength + 1, "(default)");
            PrintRegistryValue(&fpOutputAlloc, valueName, dwMaxValueNameLength, dwRegType, dataLength, bdata, false);
            
        }

        KERNEL32$HeapFree(hHeap, 0, (LPVOID)valueName);
        KERNEL32$HeapFree(hHeap, 0, (LPVOID)bdata);

    }

    BeaconFormatPrintf(&fpOutputAlloc, "\nDONE\n");

    //print output!
    int iOutputLength;
    char* beaconOutputString = BeaconFormatToString(&fpOutputAlloc, &iOutputLength);
    BeaconOutput(CALLBACK_OUTPUT, beaconOutputString, iOutputLength + 1);

    BeaconFormatFree(&fpOutputAlloc);
    ADVAPI32$RegCloseKey(hKey);
}

void PrintRegistryValue(formatp* pFormatObj, const char* valueName, DWORD dwMaxValueNameLength, DWORD dwRegType, DWORD dataLength, LPBYTE bdata, bool PrintFullBinaryData){
    const char* dataTypeString = DataTypeToString(dwRegType);

    if(dwRegType == REG_SZ || dwRegType == REG_EXPAND_SZ){
        if(dataLength == 0){
            BeaconFormatPrintf(pFormatObj, "  %s    %*s%s", valueName, dwMaxValueNameLength, "");
            return;
        }
        bdata[dataLength-1] = 0;
        BeaconFormatPrintf(pFormatObj, "  %s    %*s%s    %*s%s\n", valueName, dwMaxValueNameLength - strlen(valueName), "", dataTypeString, MAX_DATATYPE_STRING_LENGTH - strlen(dataTypeString), "", (LPSTR)bdata);

    }
    else if (dwRegType == REG_NONE)
        BeaconFormatPrintf(pFormatObj, "  %s    %*s%s\n", valueName, dwMaxValueNameLength - strlen(valueName), "", dataTypeString);
    else if(dwRegType == REG_DWORD)
        BeaconFormatPrintf(pFormatObj, "  %s    %*s%s    %*s0x%x\n", valueName, dwMaxValueNameLength - strlen(valueName), "", dataTypeString, MAX_DATATYPE_STRING_LENGTH - strlen(dataTypeString), "", *(PDWORD)bdata);
    else if(dwRegType == REG_QWORD)
        BeaconFormatPrintf(pFormatObj, "  %s    %*s%s    %*s0x%llx\n", valueName, dwMaxValueNameLength - strlen(valueName), "", dataTypeString, MAX_DATATYPE_STRING_LENGTH - strlen(dataTypeString), "", *(PULONGLONG)bdata);
    else if(dwRegType == REG_BINARY){
        BeaconFormatPrintf(pFormatObj, "  %s    %*s%s    %*s", valueName, dwMaxValueNameLength - strlen(valueName), "", dataTypeString, MAX_DATATYPE_STRING_LENGTH - strlen(dataTypeString), "");
        DWORD maxindex = dataLength;
        if(!PrintFullBinaryData && maxindex > 10)
            maxindex = 10;
        for(int j = 0; j < maxindex; j++)
            BeaconFormatPrintf(pFormatObj, "%02X", bdata[j]);
        if(maxindex != dataLength)
            BeaconFormatPrintf(pFormatObj, "... [%d total bytes]\n", dataLength);
        else
            BeaconFormatPrintf(pFormatObj, " [%d bytes]\n", dataLength);
    }
    else if(dwRegType == REG_MULTI_SZ){

        BeaconFormatPrintf(pFormatObj, "  %s    %*s%s    %*s", valueName, dwMaxValueNameLength - strlen(valueName), "", dataTypeString, MAX_DATATYPE_STRING_LENGTH - strlen(dataTypeString), "");

        bdata[dataLength-1] = 0;
        DWORD offset = 0;
        if(bdata[0] != 0){
            for(;;){
                LPSTR curString = (LPSTR)(bdata + offset);
                BeaconFormatPrintf(pFormatObj, "%s", curString);
                offset += strlen(curString) + 1;
                if(bdata[offset] == 0)
                    break;
                BeaconFormatPrintf(pFormatObj, "#");
            }
        }
        BeaconFormatPrintf(pFormatObj, "\n");
    }
    else if(dwRegType == REG_LINK){
        bdata[dataLength-1] = 0;
        if(dataLength > 1)
            bdata[dataLength-2] = 0;
        BeaconFormatPrintf(pFormatObj, "  %s    %*s%s    %*s%ls\n", valueName, dwMaxValueNameLength - strlen(valueName), "", dataTypeString, MAX_DATATYPE_STRING_LENGTH - strlen(dataTypeString), "", (LPWSTR)bdata);
    }
    else{
        BeaconFormatPrintf(pFormatObj, "  %s    %*s%s    %*s%s\n", valueName, dwMaxValueNameLength - strlen(valueName), "", dataTypeString, MAX_DATATYPE_STRING_LENGTH - strlen(dataTypeString), "", "<not supported>");
    }
}

bool ParseArguments(char * args, int arglen, PREGISTRY_OPERATION pRegistryOperation, LPCSTR *lpcRemoteComputerName, HKEY *pHiveRoot, REGSAM *pArchType, LPCSTR *lpcKeyName, LPCSTR *lpcValueName, LPDWORD pdwDataType, LPBYTE *pbData, PLONGLONG pllDataNum, LPDWORD cbData){
    datap parser;

    char* regCommand;
    char* remoteComputerName;
    char* hiveRootString;
    REGSAM archType;
    char* regKey;
    char* value;
    int emptyValue;
    int dataType;
    char* data;

    BeaconDataParse(&parser, args, arglen);

    regCommand = BeaconDataExtract(&parser, NULL);
    remoteComputerName = BeaconDataExtract(&parser, NULL);
    hiveRootString = BeaconDataExtract(&parser, NULL);
    archType = (REGSAM)BeaconDataInt(&parser);
    regKey = BeaconDataExtract(&parser, NULL);
    value = BeaconDataExtract(&parser, NULL);
    emptyValue = BeaconDataInt(&parser);
    dataType = BeaconDataInt(&parser);
    data = BeaconDataExtract(&parser, NULL);

    if(regCommand == NULL || hiveRootString == NULL){
        BeaconPrintf(CALLBACK_ERROR, "Usage: breg <command> <key> [arguments]\n");
        return false;
    }

    if( MSVCRT$_stricmp("HKLM", hiveRootString) == 0)
        *pHiveRoot = HKEY_LOCAL_MACHINE;
    else if( MSVCRT$_stricmp("HKCU", hiveRootString) == 0)
        *pHiveRoot = HKEY_CURRENT_USER;
    else if( MSVCRT$_stricmp("HKCR", hiveRootString) == 0)
        *pHiveRoot = HKEY_CLASSES_ROOT;
    else if( MSVCRT$_stricmp("HKU", hiveRootString) == 0)
        *pHiveRoot = HKEY_USERS;
    else if( MSVCRT$_stricmp("HKCC", hiveRootString) == 0)
        *pHiveRoot = HKEY_CURRENT_CONFIG;
    else{
        BeaconPrintf(CALLBACK_ERROR, "breg: Unknown registry hive '%s'\n", hiveRootString);
        return false;
    }

    if( MSVCRT$_stricmp("query", regCommand) == 0)
        *pRegistryOperation = RegistryQueryOperation;
    else if( MSVCRT$_stricmp("add", regCommand) == 0)
        *pRegistryOperation = RegistryAddOperation;
    else if( MSVCRT$_stricmp("delete", regCommand) == 0)
        *pRegistryOperation = RegistryDeleteOperation;
    else{
        BeaconPrintf(CALLBACK_ERROR, "breg: Unknown command '%s'\n", regCommand);
        return false;
    }

    *pArchType = archType;

    if(remoteComputerName == NULL || strlen(remoteComputerName) > 0)
        *lpcRemoteComputerName = remoteComputerName;
    else
        *lpcRemoteComputerName = NULL;

    if(regKey == NULL)
        regKey = "";
    *lpcKeyName = regKey;

    if(emptyValue == 1)
        *lpcValueName = NULL;
    else
        *lpcValueName = value;

    *pdwDataType = dataType;
    if(dataType == REG_NONE){
        *pbData = NULL;
        *cbData = 0;
    }
    else if (dataType == REG_SZ || dataType == REG_EXPAND_SZ){
        *pbData = data;
        *cbData = strlen(data) + 1;
    }
    else if (dataType == REG_DWORD){
        int idata = MSVCRT$atoi(data);
        *pllDataNum = (LONGLONG)idata;
        *pbData = (LPBYTE)pllDataNum;
        *cbData = 4;
    }
    else if (dataType == REG_QWORD){
        LONGLONG lldata = MSVCRT$_atoi64(data);
        *pllDataNum = lldata;
        *pbData = (LPBYTE)pllDataNum;
        *cbData = 8;
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "breg: Unknown datatype '%d'\n", dataType);
        return false;
    }

    return true;
}

const char* HiveRootKeyToString(HKEY HiveRoot){
    if(HiveRoot == HKEY_LOCAL_MACHINE)
        return "HKLM";
    if(HiveRoot == HKEY_CURRENT_USER)
        return "HKCU";
    if(HiveRoot == HKEY_CLASSES_ROOT)
        return "HKCR";
    if(HiveRoot == HKEY_USERS)
        return "HKU";
    if(HiveRoot == HKEY_CURRENT_CONFIG)
        return "HKCC";
    return "N/A";
}

const char* DataTypeToString(DWORD regType){
    if(regType == REG_SZ)
        return "REG_SZ";
    if(regType == REG_NONE)
        return "REG_NONE";
    if(regType == REG_DWORD)
        return "REG_DWORD";
    if(regType == REG_QWORD)
        return "REG_QWORD";
    if(regType == REG_BINARY)
        return "REG_BINARY";
    if(regType == REG_EXPAND_SZ)
        return "REG_EXPAND_SZ";
    if(regType == REG_MULTI_SZ)
        return "REG_MULTI_SZ";
    if(regType == REG_LINK)
        return "REG_LINK";
    return "REG_UNKNOWN";
}

const char* ArchTypeToString(REGSAM ArchType){
    if(ArchType == KEY_WOW64_64KEY)
        return "[WOW64_64KEY]";
    else if (ArchType == KEY_WOW64_32KEY)
        return "[WOW64_32KEY]";
    return "";
}

