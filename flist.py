#############################################################################
# File list - This script is able to list files in the given path and also:
# - identify whether the file is a Win PE executable or not
# - in case of executables, detect the digital signature (Authenticode)
#############################################################################

import os
import argparse
import struct

def fileHasSignature(file, filelength, debugMode = False):
    # Credits: https://github.com/ralphje/signify
    # Note: See http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx for information about the structure.
    try:        
        # Offset to e_lfanew (which is the PE header) is at 0x3C of the MZ header
        file.seek(0x3C, os.SEEK_SET)
        pe_offset = struct.unpack('<I', file.read(4))[0]
        if pe_offset >= filelength:
            raise Exception("PE header location is beyond file boundaries (%d >= %d)" %
                                    (pe_offset, filelength))

        # Check if the PE header is PE
        file.seek(pe_offset, os.SEEK_SET)
        if file.read(4) != b'PE\0\0':
            raise Exception("PE header not found")

        # The COFF header contains the size of the optional header
        file.seek(pe_offset + 20, os.SEEK_SET)
        optional_header_size = struct.unpack('<H', file.read(2))[0]
        optional_header_offset = pe_offset + 24
        if optional_header_size + optional_header_offset > filelength:
            # This is not strictly a failure for windows, but such files better
            # be treated as generic files. They can not be carrying SignedData.
            raise Exception("The optional header exceeds the file length (%d + %d > %d)" %
                                    (optional_header_size, optional_header_offset, filelength))

        if optional_header_size < 68:
            # We can't do authenticode-style hashing. If this is a valid binary,
            # which it can be, the header still does not even contain a checksum.
            raise Exception("The optional header size is %d < 68, which is insufficient for authenticode",
                                    optional_header_size)

        # The optional header contains the signature of the image
        file.seek(optional_header_offset, os.SEEK_SET)
        signature = struct.unpack('<H', file.read(2))[0]

        if signature == 0x10b:  # IMAGE_NT_OPTIONAL_HDR32_MAGIC
            rva_base = optional_header_offset + 92  # NumberOfRvaAndSizes
            cert_base = optional_header_offset + 128  # Certificate Table
        elif signature == 0x20b:  # IMAGE_NT_OPTIONAL_HDR64_MAGIC
            rva_base = optional_header_offset + 108  # NumberOfRvaAndSizes
            cert_base = optional_header_offset + 144  # Certificate Table
        else:
            # A ROM image or such, not in the PE/COFF specs. Not sure what to do.
            raise Exception("The PE Optional Header signature is %x, which is unknown", signature)

        # Read the RVA
        if optional_header_offset + optional_header_size < rva_base + 4:
            raise Exception("The PE Optional Header size can not accommodate for the NumberOfRvaAndSizes field")

        file.seek(rva_base, os.SEEK_SET)
        number_of_rva = struct.unpack('<I', file.read(4))[0]
        if number_of_rva < 5:
            raise Exception("The PE Optional Header does not have a Certificate Table entry in its Data Directory; "
                         "NumberOfRvaAndSizes = %d", number_of_rva)
        if optional_header_offset + optional_header_size < cert_base + 8:
            raise Exception("The PE Optional Header size can not accommodate for a Certificate Table entry in its Data "
                         "Directory")

        # Read the certificate table entry of the Data Directory
        file.seek(cert_base, os.SEEK_SET)
        address, size = struct.unpack('<II', file.read(8))

        if not size:
            raise Exception("The Certificate Table is empty")

        if address < optional_header_size + optional_header_offset or address + size > filelength:
            raise Exception("The location of the Certificate Table in the binary makes no sense and is either beyond the "
                         "boundaries of the file, or in the middle of the PE header; "
                         "VirtualAddress: %x, Size: %x", address, size)
    except Exception as e:
        if debugMode: print(e)
        return False
    else:
        return True

try:
    # init argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", help = "List files within a specified path")
    args = parser.parse_args()

    targetPath = args.path if args.path else os.getcwd() # user specified path or current if --path is not set

    assert (os.path.exists(targetPath)), f"Path '{targetPath}' does not exists." # check if path exists

    results = []

    for fileName in os.listdir(targetPath):
        filePath = os.path.join(targetPath, fileName)
        if not os.path.isfile(filePath): continue # consider only files

        with open(filePath, "rb") as file:

            file.seek(0, os.SEEK_END)
            filelength = file.tell()

            # Check if file starts with MZ
            file.seek(0, os.SEEK_SET)
            if file.read(2) == b'MZ':
                isExec = "Yes"
                isSigned = "Yes" if fileHasSignature(file, filelength, True) else "No"
            else:
                isExec = "No"
                isSigned = "No"

            
        
        #isExec = "Yes" if open(fPath, "rb").read(2) == b"MZ" else "No" # TBD.. here i consider an executable if the files contains the win pe mz tag

 
        results += [[fileName, isExec, isSigned]]
    
    assert (results), f"Path '{targetPath}' does not contain any files"

    results = [['File Name', 'Executable', 'Signed']] + results # add header on top

    # check if path contains files
    # if not files:
    #     print(f"Path '{targetPath}' is empty.")
    #     exit()

    print(f"Listing files in path '{targetPath}':")

    col_width = max(len(word) for row in results for word in row) + 2  # get maximum column width /w padding

    for row in results:
        print(("{: <%d} {: >10} {: >10}" % col_width).format(*row))

except Exception as e:
    print(f"An error occurred: {e}")