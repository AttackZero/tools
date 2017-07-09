#!/usr/bin/env python3

### Imports ###
import argparse, os, sys, collections, re, threading, time, datetime, hashlib

### Constants ###
## Regex ##
# Match all sets of 3 or more spaces, numbers, and letters
reThreePrintable = re.compile('[\w\s\d\p]{3,}')

# Match a credit card number (16 digits in 4 groups with or without a separator)
reCreditCard = re.compile('(\d{4}[-\s]?){3}\d{4}')

defaultFilters = [ reThreePrintable, reCreditCard ]

### Classes ###

class ThreadedWorker():  
    def __init__(self, pid, outputFile, lock):
        self.results = []
        self.name = str(pid)
        self.pid = pid
        self.memRegions = {}
        self.stopLock = threading.Event()
        self.regionBlacklist = []
        self.thread = threading.Thread(target=self.doWork)
        self.filters = defaultFilters
        self.file = outputFile
        self.printLock = lock
        # The number of seconds between re-reading each memory region
        self.regionScanInterval = 30

        self.FindMemoryRegionsForPID(self.pid, self.memRegions)
    
    def FindMemoryRegionsForPID(self, pid, regions):
        try:
            print('[{0}] Scanning PID {1} for memory changes...'.format(datetime.datetime.now().strftime('%H:%M.%S'), self.pid))
            with open('/proc/{0}/maps'.format(pid), 'r') as regionInfo:
                for region in regionInfo:
                    # Right now we are focusing on the dynamically allocated sections of memory
                    '''
                    We could do every region, but since many regions are
                    simply imports of files, we want to focus on the heap and stack
                    where dynamically assigned information should be.
                    We could easily remove the limiter to return all regions.
                    '''
                    regionSplit = region.split()
                    if 'r' not in regionSplit[1] or len(regionSplit) != 6: # there should be 6 columns
                        continue
                    # The path name is the last column
                    #if regionSplit[-1] == '[heap]' or regionSplit[-1].startswith('[stack'):
                    regionStartEnd = regionSplit[0].split('-')
                    # The address is in hex, so we will cast it to a base 16 (hex) int
                    startOfRegion = int(regionStartEnd[0], 16)
                    if startOfRegion in self.regionBlacklist:
                        continue
                    endOfRegion = int(regionStartEnd[1], 16)
                    if startOfRegion not in regions:
                        print('[{0}] Found a new region in PID {1}'.format(datetime.datetime.now().strftime('%H:%M.%S'), self.pid))
                        regions[startOfRegion] = { 'size': endOfRegion - startOfRegion,
                                                   'hash': '',
                                                   'lastHash': ''
                                                 }
        except:
             self.stopLock.set()
        return
        
    def ScanMemoryRegion(self, region, regionData):
        try:
             print('[{0}] Scanning memory region <<{1}: {2} ({3:,} bytes)>> for changes...'.format(datetime.datetime.now().strftime('%H:%M.%S'), self.pid, hex(region), regionData['size']))
             with open('/proc/{0}/mem'.format(self.pid), 'rb', 0) as memory:
                 memory.seek(region)
                 rawBytes = memory.read(regionData['size'])
                 regionData['hash'] = hashlib.sha1(rawBytes).hexdigest()
             decodedBytes = rawBytes.decode('utf-8', errors='ignore')
        except OverflowError:
            print('[{0}] Region <<{1}>> is outside of scannable memory space.  Skipping...'.format(datetime.datetime.now().strftime('%H:%M.%S'), hex(region)))
            self.regionBlacklist.append(region)
            return None
        except OSError:
            print('[{0}] Region <<{1}>> is not scannable.  Skipping...'.format(datetime.datetime.now().strftime('%H:%M.%S'), hex(region)))
            self.regionBlacklist.append(region)
            return None
        except: # Then something went terribly wrong (like the process closing)
             self.stopLock.set()
             return None
        print('[{0}] Scanning of region <<{1}: {2}>> complete'.format(datetime.datetime.now().strftime('%H:%M.%S'), self.pid, hex(region)))
        return decodedBytes

    def doWork(self):
        #while self.running:
        while not self.stopLock.is_set():
            # Scan memory
            # find strings
            # Add ones we do not have to internal list
            self.FindMemoryRegionsForPID(self.pid, self.memRegions)
            if self.stopLock.is_set(): # then the process likely exited
                print('[!!!] [{0}] Could not gather memory allocation information for PID {1}.  This thread will terminate.  Please wait for the next monitor sync.'.format(datetime.datetime.now().strftime('%H:%M.%S'), self.pid))
                self.regionScanInterval = 0
                break
            for region in self.memRegions:
                currentRegion = self.ScanMemoryRegion(region, self.memRegions[region])
                if self.stopLock.is_set(): # then the process likely exited
                    print('[!!!] [{0}] Could not scan region for PID {1}.  This thread will terminate.  Please wait for the next monitor sync.'.format(datetime.datetime.now().strftime('%H:%M.%S'), self.pid))
                    self.regionScanInterval = 0
                    break
                print('[{0}] Region {1} / Last: {2}; Current: {3} ({4})'.format(datetime.datetime.now().strftime('%H:%M.%S'), hex(region), self.memRegions[region]['lastHash'] if self.memRegions[region]['lastHash'] != '' else 'N/A', self.memRegions[region]['hash'], 'SAME' if self.memRegions[region]['lastHash'] == self.memRegions[region]['hash'] else 'CHANGED'))
                if self.memRegions[region]['lastHash'] == self.memRegions[region]['hash']:
                    continue
                    
                for filt in self.filters:
                    currentResults = re.findall(filt, currentRegion)
                    if len(currentResults) > 0:
                        newResults = set(currentResults).symmetric_difference(set(self.results)) # set difference (symmetric_difference)
                        print('[{0}] Found {1:,} new results from PID {2}, region {3}'.format(datetime.datetime.now().strftime('%H:%M.%S'), len(newResults), self.pid, hex(region)))
                        self.results.extend(list(newResults))

                        for result in newResults:
                            if self.file:
                                self.printLock.acquire()
                                self.file.write(result + '\n')
                                self.file.flush()
                                self.printLock.release()
                self.memRegions[region]['lastHash'] = self.memRegions[region]['hash']
    
            if not self.stopLock.is_set(): # No errors this run, so we will keep going
                print('[{0}] Waiting {1} seconds before rescanning PID {2}...\n'.format(datetime.datetime.now().strftime('%H:%M.%S'), self.regionScanInterval, self.pid))

            self.stopLock.wait(self.regionScanInterval)
    
    def getProgress(self):
        return len(self.results)
    
    def terminate(self):
        #self.running = False
        self.stopLock.set()
        self.thread.join(timeout=0)
    
    def terminated(self):
        return self.stopLock.is_set()
        
    def getResults(self):
        return self.results
    
    def start(self):
        self.running = True
        self.thread.start()
    
    def getPID(self):
        return self.pid
        
    def getThread(self):
        return self.thread


### Globals ###

# ptrace status
ptraceStatus = '0'

# Process Information Dictionary
'''
The dictionary is keyed by PID, and contains the following
values:

ownerUID: the UID of the owner of the PID
name: the name of the process with this PID
'''
processInformation = collections.defaultdict(dict)

def GatherProcessInformation():
    global processInformation

    for entry in os.listdir('/proc'):
        if entry.isdigit() and os.path.isdir('/proc/' + entry):
            with open('/proc/{0}/status'.format(entry), 'r') as procStatus:
                for line in procStatus:
                    if line.startswith('Uid:'):
                        # The lines usually look something like this: Uid: 0 0 0 0
                        # Then the UID is the first digit in the line (position 1)
                        processInformation[entry]['ownerUID'] = int(line.split('\t')[1])
                    elif line.startswith('Name:'):
                        processInformation[entry]['name'] = line.strip().split('\t')[1]
    return
    
'''
    This function looks for any processes that have spawned with any of the process names
    we are interested in.  If so, it will return a list of new PIDs so that new workers
    will be created.  The processInformation state table will also be updated.
'''
def UpdateProcessInformation(pNameList):
    global processInformation
    
    newPID = []
    newEntry = False
    newUID = 0
    
    for entry in os.listdir('/proc'):
        if entry.isdigit() and os.path.isdir('/proc/' + entry) and entry not in processInformation:
            with open('/proc/{0}/status'.format(entry), 'r') as procStatus:
                for line in procStatus:
                    if line.startswith('Name:'):
                        pName = line.strip().split('\t')[1]
                        if pName in pNameList:
                            processInformation[entry]['name'] = pName
                            newEntry = True
                            newPID.append(entry)
                    elif line.startswith('Uid'):
                        newUID = int(line.split('\t')[1])
                if newEntry:
                    processInformation[entry]['ownerUID'] = newUID
                newEntry = False
    
    return newPID
                    

def ValidatePIDList(argument):
    try:
        potentialPIDList = argument.replace(' ', '').split(',')
    except:
        raise argparse.ArgumentTypeError('The PID must be a list of PIDs separated by commas or a single PID.  "{0}" is not a valid.'.format(argument))
    
    # Do a sanity check on the list of PIDs.  They all have to be integers.
    if not all(pid.isdigit() for pid in potentialPIDList):
        raise argparse.ArgumentTypeError('All PIDs supplied must be integers.')
    
    # Check if all pids in the list are actually running by comparing them against the info we gathered
    #if not all(pid in processInformation for pid in potentialPIDList):
    
    for pid in potentialPIDList:
        if pid not in processInformation:
            raise argparse.ArgumentTypeError('{0} is not a valid PID.'.format(pid))
    
    '''
    Depending on ptraceStatus, we need to see if all of the processes we want to examine are
    owned by the current UID.  This only matters if ptraceStatus is 0.  If it is 1 or 2,
    we have to be root, which was checked before we got here.  If ptraceStatus is 3,
    we should have exited by now.
    '''
    currentUID = os.getuid()
    if (ptraceStatus == '0' and currentUID != 0) and not all(processInformation[pid]['ownerUID'] == currentUID for pid in potentialPIDList):
        raise argparse.ArgumentError('You must be root to use this program against PIDs that are not running as your user.')
    
    return potentialPIDList
    
    
def ValidatePNames(argument):
    try:
        potentialPNameList = argument.replace(' ', '').split(',')
    except:
        raise argparse.ArgumentTypeError('The name argument must be a list of process names separated by commas or a single process name.  "{0}" is not a valid.'.format(argument))
    
    # See if all of those process names are actually running and that they conform to any ptrace restrictions
    # We will only gather those PIDs that meet the two conditions above
    pidList = []
    currentUID = os.getuid()
    pNameListValid = False

    # Invert processInformation on name
    # We could do this with a dictionary comprehension, like this:
    # pInfoByName = {processInformation[pid]['name']: {'pid':pid, 'ownerUID': processInformation[pid]['ownerUID']} for pid in processInformation}
    # However, this will wipe out any process names that map to multiple PIDs
    pInfoByName = {}    
    for pid in processInformation:
        pidName = processInformation[pid]['name']
        if pidName in pInfoByName:
            pInfoByName[pidName]['pid'].append(pid)
            if processInformation[pid]['ownerUID'] not in pInfoByName[pidName]['ownerUID']:
                pInfoByName[pidName]['ownerUID'].append(processInformation[pid]['ownerUID'])
        else:
            pInfoByName[pidName] = {}
            pInfoByName[pidName]['pid'] = [ pid ]
            pInfoByName[pidName]['ownerUID'] = [ processInformation[pid]['ownerUID'] ]
    
    #if not all(pName in pInfoByName for pName in potentialPNameList):
     #   print('One or more of the process names supplied is not running.  Please verify the list and try again.')
      #  sys.exit()

    for pName in pInfoByName:
        if pName in potentialPNameList:
            if ptraceStatus == '0' and currentUID != 0:
                for pid in pInfoByName[pname]['pid']:                
                    if processInformation[pid]['ownerUID']:
                        pidList.append(pid) 
            else:
                pidList.extend(pInfoByName[pName]['pid'])
                
    
    #if len(pidList) == 0: # then we did not find any suitable PIDs
    #    raise argparse.ArgumentTypeError('Could not find any PIDs with any of the supplied process names.  Please try again.')
    #else:
    #    return pidList, potentialPNameList
    return pidList, potentialPNameList

def ClearScreen():
    os.system('clear')
    
def ValidateEnvironment():
    if os.name != 'posix':
        print('This script only runs on *nix.  Exiting...')
        sys.exit()
        
    # Check ptrace status
    global ptraceStatus
    '''
    If ptrace_scope does not exist, then we should be in an environment
    equivalent to ptrace_scope being 0
    
    If it is anything but 0, we will figure that out now.
    '''
    
    if os.path.isfile('/proc/sys/kernel/yama/ptrace_scope'):
        with open('/proc/sys/kernel/yama/ptrace_scope', 'r') as ptraceStatusFile:
            ptraceStatus = ptraceStatusFile.readline().strip()
            #if ptraceStatus == '0' then we do not need to be root, but any PIDs must be owned by this UID
            if ptraceStatus == '1' or ptraceStatus == '2': # then we need to be root for our purposes
                if os.getuid() != 0: # not root
                    print('You must be root in order to execute this script.  Check /proc/sys/kernel/yama/ptrace_scope.  Exiting...')
                    sys.exit()
            elif ptraceStatus == '3':
                print('Attaching to processes with PTrace is disabled on this system.  This functionality is required for this program to function.  Exiting...')
                sys.exit()
                
    return ptraceStatus

if __name__ == '__main__':
    ValidateEnvironment()
    GatherProcessInformation()
    commandArgumentParser = argparse.ArgumentParser(description='ProcScan: Process Memory Scanner')
    
    processArgumentsGroup = commandArgumentParser.add_mutually_exclusive_group(required=True)
    processArgumentsGroup.add_argument('-pid', type=ValidatePIDList, help='PID to examine (one or more): 100 or 100,200,...', metavar='list_of_pids') #,type=CheckIfPIDExists: return PID int value if PID exists, raise exception otherwise
    processArgumentsGroup.add_argument('-name', type=ValidatePNames, help='Name of process(es) to examine, separated by commas', metavar='process_name') #,type=CheckIfPNameExists
    commandArgumentParser.add_argument('-o', help='Optional output file', metavar='file')
    
    clArguments = commandArgumentParser.parse_args()
    print('Args: {0}'.format(clArguments))

    if clArguments.o:
        outputFile = open(clArguments.o, 'w')
    else:
        outputFile = None

    printLock = threading.Lock()
    
    if clArguments.name: # then we will process by name
        pidList = clArguments.name[0]
        procName = clArguments.name[1]
        processByName = True
    else:
        pidList = clArguments.pid
        procName = ''
        processByName = False
    
    # Initialize workers
    workers = []
    for pid in pidList:
        currentWorker = ThreadedWorker(pid, outputFile, printLock)
        currentWorker.start()
        workers.append(currentWorker)
    
    print('Initialized with {0} processes...'.format(len(pidList)))
    print('Starting work {0} monitor...'.format('and process' if processByName else ''))
    interrupted = False
    resultTotal = 0
    
    while True:
        try:
            print('---- Progress (Next update at: {0}) ----'.format((datetime.datetime.now() + datetime.timedelta(minutes=1)).strftime('%H:%M.%S')))
            if processByName:
                print('[{0}] Checking for new processes that match supplied process names...'.format(datetime.datetime.now().strftime('%H:%M.%S')))
                newPIDs = UpdateProcessInformation(procName)
                if len(newPIDs) > 0: # then we found new processes
                    print('[{0}] {1} new PID{2} found.  Attaching...'.format(datetime.datetime.now().strftime('%H:%M.%S'), len(newPIDs), 's' if len(newPIDs) > 1 else ''))
                    pidList.extend(newPIDs)
                    for pid in newPIDs:
                        currentWorker = ThreadedWorker(pid, outputFile, printLock)
                        currentWorker.start()
                        workers.append(currentWorker)
                else:
                    print('[{0}] No new processes found.  Continuing.'.format(datetime.datetime.now().strftime('%H:%M.%S')))
            for worker in workers:
                print('[{0}] PID {1}: {2:,} matches'.format(datetime.datetime.now().strftime('%H:%M.%S'), worker.getPID(), worker.getProgress()))
                resultTotal += worker.getProgress()
            
            print('[{0}] Total matches gathered across all ({1}) PID{2} so far: {3:,}\n'.format(datetime.datetime.now().strftime('%H:%M.%S'), len(pidList), 's' if len(pidList) > 1 else '', resultTotal))
            
            resultTotal = 0 # reset
            
            if len(workers) > 0 and all(worker.terminated() for worker in workers):
                print('\n[!!!] [{0}] All workers have terminated unexpectedly.  Cleaning up and exiting...'.format(datetime.datetime.now().strftime('%H:%M.%S')))
                break
            time.sleep(60)
        except KeyboardInterrupt:
            print('[*] [{0}] Received signal to terminate.  Cleaning up...'.format(datetime.datetime.now().strftime('%H:%M.%S')))
            interrupted = True
            break

    if interrupted:            
        for worker in workers:
            worker.terminate()
        
    if outputFile:
        outputFile.close()
        
    print('[{0}] Clean up complete.  Execution terminated.'.format(datetime.datetime.now().strftime('%H:%M.%S')))
