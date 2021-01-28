# Registry BOF

A beacon object file for use with cobalt strike v4.1+. Supports querying, adding, and deleting keys/values and local and remote registries.

## Usage

```
beacon> help breg
Queries, adds, or deletes keys/values in the windows registry using a beacon object file

Usage: breg <command> <key> [/v value] [/t type] [/d data] [/a arch]
   - command: 'query', 'add', or 'delete'. Other registry commands are not supported at this time
   - key: A windows registry key
      - If local must start with HKLM, HKCU, HKCR, HKU, or HKCC
      - If remote must be of the form \\computername\hiveroot[\subkey], where hiveroot is one of the aforementioned keys
   - value: A value to query, add, or delete if dealing with values. Specify an empty string to manipulate the default value of a key (equivalent to /ve)
   - type: One of the following: REG_SZ, REG_NONE, REG_DWORD, REG_QWORD, REG_EXPAND_SZ. Other types are not supported at this time. Default is REG_SZ
   - data: Data to add if adding a value. This value is required when adding a value unless the type is REG_NONE
   - arch: The version of the registry to check. Can be 'x64' or 'x32'. Default is the arch of the current beacon
```

## Examples

Enumerating a registry key:
```
beacon> breg query HKCU\Testing
[*] Tasked beacon to run breg query HKCU\Testing
[+] host called home, sent: 12231 bytes
[+] received output:

[HKCU\Testing] 

Subkeys [4]:

  HKCU\Testing\Key1
  HKCU\Testing\Key2
  HKCU\Testing\Key3
  HKCU\Testing\Key4

Values [10]:

  Name                  Type             Data
  ----                  ----             ----
  (default)             REG_SZ           
  Value1                REG_SZ           Data1
  Value2                REG_SZ           Data2
  Value3                REG_SZ           Data3
  NumTest               REG_DWORD        0x21
  NumTest2              REG_DWORD        0xff
  MyQword               REG_QWORD        0xb3a73ce2ff2
  MyBinaryData          REG_BINARY       01234567876543211093... [29 total bytes]
  MyExpandString        REG_EXPAND_SZ    %windir%\system32\myfile.exe
  MultiVal              REG_MULTI_SZ     string1#string2#string3 with space#string4

DONE
```

Deleting a key:
```
beacon> breg query "HKCU\Key With Space"
[*] Tasked beacon to run breg query "HKCU\Key With Space"
[+] host called home, sent: 12266 bytes
[+] received output:

[HKCU\Key With Space] 

Subkeys [2]:

  HKCU\Key With Space\Subkey1
  HKCU\Key With Space\Subkey2

Values [1]:

  Name         Type             Data
  ----         ----             ----
  Value1       REG_SZ           My Data

DONE

beacon> breg delete "HKCU\Key With Space\Subkey1"
[*] Tasked beacon to run breg delete "HKCU\Key With Space\Subkey1"
[+] host called home, sent: 12275 bytes
[+] received output:

 Deleted key 'HKCU\Key With Space\Subkey1' 

DONE

beacon> breg query "HKCU\Key With Space"
[*] Tasked beacon to run breg query "HKCU\Key With Space"
[+] host called home, sent: 12266 bytes
[+] received output:

[HKCU\Key With Space] 

Subkeys [1]:

  HKCU\Key With Space\Subkey2

Values [1]:

  Name         Type             Data
  ----         ----             ----
  Value1       REG_SZ           My Data

DONE
```

Adding a value:
```
beacon> breg query HKCU\Testing /v NewKey
[*] Tasked beacon to run breg query HKCU\Testing /v NewKey
[+] host called home, sent: 12265 bytes
[-] breg: Failed to query value 'NewKey' in key 'HKCU\Testing' [error 2]

beacon> breg add HKCU\Testing /v NewKey /t REG_DWORD /d 0x11223344
[*] Tasked beacon to run breg add HKCU\Testing /v NewKey /t REG_DWORD /d 0x11223344
[+] host called home, sent: 12272 bytes
[+] received output:

 Added value 'NewKey' to 'HKCU\Testing' 

DONE

beacon> breg query HKCU\Testing /v NewKey
[*] Tasked beacon to run breg query HKCU\Testing /v NewKey
[+] host called home, sent: 12265 bytes
[+] received output:

[HKCU\Testing] 

  Name      Type             Data
  ----      ----             ----
  NewKey    REG_DWORD        0x11223344

DONE
```

## Extra Notes
- REG_BINARY values are truncated to 10 bytes when enumerating a key, but the entire value is displayed when querying the speicfic value.
- The '#' character is used to delineate strings within type REG_MULTI_SZ
- the `breg add` command will overwrite a value if it already exists when adding a value
- the `breg delete` command will delete all subkeys and values of a key if deleting a key (if deleting a value only the one value is deleted)

## Misc: Helper Function
There is a helper function `breg_add_string_value` that can be called by a separate alias or function to add a string value to a registry. This could be used to enhance the stealthiness of an existing script that adds registry values (for example a script that establishes persistence). An example alias that calls the function is included at the bottom of `breg.cna`. At the moment the only helper function that exists is one that adds strings.
