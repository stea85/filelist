# filelist (File listing excercise)
A Python command line tool designed __for Windows only__ that lists files in a given path and provides the following output:
- Filename
- Executable (Yes/No)
- Signed (Yes/No)

# Definitions
- _Executable_: A Windows PE executable image. This is determined by reading the file header and looking for bytes 0x5A4D (MZ in ASCII) a DOS header that is always present
- _Signed_: When file is executable, the tool will run PowerShell cmdlet 'Get-Authenticode' to detect and verify a digital signature (both embedded and catalog signatures)

# How to use
```
python flist.py --path [target_directory]
python flist.py --path [target_directory] --recursive
```

## Sample output
```
Listing files in path 'C:\sample':
File Name            Executable     Signed
d3dcompiler_47.dll          Yes        Yes
msedge.exe                  Yes        Yes
Mullvad VPN.exe             Yes         No
q.log                        No         No
```
A log file named "log.txt" is also generated within the same directory as the script.


Ref.: 
- https://en.wikipedia.org/wiki/Portable_Executable
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode
