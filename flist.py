#############################################################################
# File list - This script is able to list files in the given path and also:
# - identify whether the file is a Win PE executable or not
# - in case of executables, detect the digital signature (Authenticode)
#############################################################################

import os
import argparse
import struct
import logging
import subprocess

# Create a logger - can be useful to review long outputs
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)-8s %(message)s',
    handlers=[
        logging.StreamHandler()
        , logging.FileHandler('log.txt')
    ]
)
logger = logging.getLogger("flist")

try:
    # init argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", help = "List files within a specified path")
    parser.add_argument("-r", "--recursive", help = "Recursively iterate through sub directories from the specified path", action='store_true')
    args = parser.parse_args()
    
    targetPath = args.path if args.path else os.getcwd() # user specified path or current if --path is not set
    assert (os.path.exists(targetPath)), f"Path '{targetPath}' does not exists." # check if path exists    

    results = []
    
    for current_dir, subdirs, files in os.walk(targetPath):
        for fileName in files:
            filePath = os.path.join(current_dir, fileName)

            if not os.path.isfile(filePath): 
                continue # consider only files

            with open(filePath, "rb") as file:
                file.seek(0, os.SEEK_END)
                filelength = file.tell()

                # Check if file header starts with MZ
                file.seek(0, os.SEEK_SET)
                if file.read(2) == b'MZ':
                    isExec = "Yes"
                    out = None
                    proc = subprocess.Popen("powershell.exe (Get-AuthenticodeSignature '" + filePath.replace("'", "''") + "').Status", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    out, err = proc.communicate()
                    isSigned = "Yes" if out is not None and out.decode() == "Valid" + os.linesep else "No"
                else:
                    isExec = "No"
                    isSigned = "No"
            results += [[filePath.replace(targetPath, "").lstrip(os.path.sep), isExec, isSigned]]
        if not args.recursive:
            break
    
    assert (results), f"Path '{targetPath}' does not contain any files"

    results = [['File Name', 'Executable', 'Signed']] + results # add header on top

    print(f"Listing files in path '{targetPath}':")

    col_width = max(len(word) for row in results for word in row) + 2  # get maximum column width /w padding

    for row in results:
        logger.info(("{: <%d} {: >10} {: >10}" % col_width).format(*row))

except Exception as e:
    print(f"An error occurred: {e}")