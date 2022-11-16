import os
import subprocess
from threading import Thread
import time
import argparse
import logging

class FolderEntry:
    def __init__(self, folderPath):
        self._folderPath = folderPath
        self._fileList = []
        self._isRunning = False

    def getFileList(self):
        return self._fileList

    def getIsRunning(self):
        return self._isRunning

    def addFile(self, filePath):
        self._fileList.append(FileEntry(filePath))

    def doItNow(self):
        self._isRunning = True
        searchPattern = os.path.join(self._folderPath, "*.*")
        cmd = "powershell.exe -Command \"Get-ChildItem " + searchPattern + " | ForEach-object {Get-AuthenticodeSignature $_} | where {$_.status -eq 'Valid'} | foreach { $_.Path }\""
        # Calling PS cmdlet Get-AuthenticodeSignature to determine whether we are dealing with a signed PE file (check box embedded and catalog signatures)
        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = proc.communicate()
        signedFilePathsList = out.decode().splitlines()

        for f in self._fileList:
            if(f.detectExecutableHeader()):
                matches = set(signedFilePathsList).intersection(set([f.getFilePath()]))
                f.setIsSigned(True if len(matches) > 0 else False)

        self._isRunning = False
        return self

    def getThreadId(self):
        return self._threadId

class FileEntry:
    def __init__(self, filePath):
        self._filePath = filePath
        self._isExecutable = False
        self._isSigned = False

    def getFilePath(self):
        return self._filePath

    def setIsSigned(self, val):
        self._isSigned = val
        
    def detectExecutableHeader(self):
        with open(self._filePath, "rb") as file:
            if file.read(2) == b'MZ': # This is a PE file
                self._isExecutable = True
        return self._isExecutable

    def getRow(self):
        return [self._filePath, self._isExecutable, self._isSigned]
    
    def getPrintable(self, basePath):
        maxFileNameLen = 40
        printName = self._filePath.replace(basePath, "").lstrip(os.path.sep)        
        return [printName[:maxFileNameLen] + "..." if len(printName) > maxFileNameLen else printName
                    , "Yes" if self._isExecutable else "No"
                    , "Yes" if self._isSigned else "No"]

def getMoreWork():
    try:
        while True:
            currentJob = queue.pop(0) # Get first item in queue (if any)
            assigned.append(currentJob)
            currentJob.doItNow()
    except Exception as e:
        return True # All good - queue is empty now - good job!

def getRunningJobs():
    runningJobs = len(queue)
    for job in assigned:
        runningJobs += 1 if job.getIsRunning() else 0
    return runningJobs

def whereAreWeNow():    
    while True:
        print('Working hard here, %d folders remaining.. please hold on (or hit CTRL+C to stop)' % getRunningJobs(), end='\r')
        if getRunningJobs() > 0: time.sleep(1)
        else: break
        
    #print('\n', end='\r')
    print('\nFile processing completed')

def main():
    logger = logging.getLogger("flist")

    global queue, assigned
    queue                   = [] # FolderEntry records waiting to be processed
    assigned                = [] # FolderEntry records in progress / completed
    max_concurrent_threads  = 5 # TODO: Make this setting parametric / user performance tuning

    fileFound = False

    # File discovery and queue
    for current_dir, subdirs, files in os.walk(targetPath):
        folder = FolderEntry(current_dir)
        queue.append(folder) # Queue up discovered folder - it will be picked up by the worker threads
        for fileName in files:
            filePath = os.path.join(current_dir, fileName)
            if not os.path.isfile(filePath): 
                continue # consider only files
            fileFound = True
            folder.addFile(filePath)
        if not args.recursive:
            break
    
    assert (fileFound), f"Path '{targetPath}' does not contain any files"

    # Create desired worker threads
    threads = []    
    threads.append(Thread(target=whereAreWeNow)) # This is just a monitoring thread to track the progress of file processing
    for t in range(0, max_concurrent_threads):
        threads.append(Thread(target=getMoreWork))

    # Lets go!
    for thread in threads:
        thread.start()

    # .. and then wait for the threads to complete
    for thread in threads:
        thread.join()

    printableResults = [['File Name', 'Executable', 'Signed']] + [f.getPrintable(targetPath) for fold in assigned for f in fold.getFileList()] # add header on top

    logger.info(f"Listing files in path '{targetPath}':")

    col_width = max(len(word) for row in printableResults for word in row) + 2  # get maximum column width /w padding

    for row in printableResults:
        logger.info(("{: <%d} {: >10} {: >10}" % col_width).format(*row))

if __name__ == "__main__":
    try:
        # Create a logger
        logging.basicConfig(
            level=logging.DEBUG,
            format='[%(asctime)s] %(levelname)-8s %(message)s',
            handlers=[
                logging.StreamHandler()
                , logging.FileHandler('log.txt')
            ]
        )
        logger = logging.getLogger("flist")

        # init argument parser
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--path", help = "List files within a specified path")
        parser.add_argument("-r", "--recursive", help = "Recursively iterate through sub directories from the specified path", action='store_true')
        args = parser.parse_args()
        
        targetPath = args.path if args.path else os.getcwd() # user specified path or current if --path is not set
        assert (os.path.exists(targetPath)), f"Path '{targetPath}' does not exists." # check if path exists    

        main()
    except Exception as e:
        print(f"An error occurred: {e}")