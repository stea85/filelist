# filelist (File listing excercise)
A Python command line tool designed __for Windows only__ that lists files in a given path and provides the following output:
- Filename
- Executable (Yes/No)
- Signed (Yes/No)

# Definitions
- _Executable_: A Windows PE executable image. This is determined by reading the file header and looking for bytes 0x5A4D (MZ in ASCII) a DOS header that is always present
- _Signed_ similar to the Executable field, this is determined by parsing the file header - more specifically this is looking for the _CertificateTable_ part within the _Optional Header_ 

# How to use
python flist.py --path [target_directory]
python flist.py --path [target_directory] --recursive

## Sample output
```
Listing files in path 'C:\sample':
File Name            Executable     Signed
d3dcompiler_47.dll          Yes        Yes
msedge.exe                  Yes        Yes
Mullvad VPN.exe             Yes         No
q.log                        No         No
```



Ref.: 
- https://en.wikipedia.org/wiki/Portable_Executable
- https://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx

# Thanks
https://github.com/ralphje/signify
