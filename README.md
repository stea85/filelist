# filelist (File listing excercise)
A Python command line tool designed __for Windows only__ that lists files in a given path and provides the following output:
- Filename
- Executable (Yes/No)
- Signed (Yes/No)

# How to use
python flist.py --path [target_directory]

## Sample output
```
Listing files in path 'C:\sample':
File Name            Executable     Signed
d3dcompiler_47.dll          Yes        Yes
msedge.exe                  Yes        Yes
Mullvad VPN.exe             Yes         No
q.log                        No         No
```

# Insights
- _Executable_ is determined based on the "MZ" file header - any windows executable file must have this 2 bytes header
- _Signed_ similar to the Executable field, this is determined by parsing the file header - more specifically this is looking for the _CertificateTable_ part within the _Optional Header_ 

Ref.: 
- https://en.wikipedia.org/wiki/Portable_Executable
- https://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx

# Thanks
https://github.com/ralphje/signify
