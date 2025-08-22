# A Delphi symbol name recovery tool. Uses after-compilation metadata to reconstruct symbols of function signatures. 
#@author Lukas Wenz - https://github.com/WenzWenzWenz
#@category Delphi
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra


import pyghidra  # type: ignore
import typing
if typing.TYPE_CHECKING:
   from ghidra.ghidra_builtins import *  # type: ignore
# from ghidra.program.model.data import PointerDataType, CategoryPath  # type: ignore
from ghidra.program.model.data import *  # type:ignore
from ghidra.program.model.symbol import SourceType, Namespace  # type: ignore
from ghidra.program.model.listing import ParameterImpl, Function  # type: ignore
from ghidra.program.model.data import IntegerDataType, CharDataType, StructureDataType, DataTypeConflictHandler  # type: ignore
from ghidra.program.model.mem import MemoryAccessException, Memory, MemoryBlock  # type: ignore
from ghidra.program.model.address import Address, AddressOutOfBoundsException  # type:ignore
from ghidra.util.exception import InvalidInputException, DuplicateNameException  # type:ignore

# this global variable is currently used for debugging purposes only
types = set()

##########################################################################
#    CONFIGS'n'CONSTANTS                                                 #
##########################################################################
# set whether or not to print detailed debug information to stdout
VERBOSE_DETAIL = False
# set whether or not to print detailed debug information to stdout
VERBOSE_DEBUG = False
# set whether or not to print less detailed debug information to stdout
VERBOSE_INFO  = True
# set whether or not to print warning information to stdout
VERBOSE_WARNING  = False

# set these variables to specific hexadecimal address strings to narrow the analysed address range, e.g.:
# STARTADDR = "005c12dc"
STARTADDR = None
ENDADDR = None

# TODO: work on: non exhaustive list of non-RTTI dependant types and make this feature toggleable
dataTypeMapping = {
    "Boolean": BooleanDataType,
    "void": VoidDataType,
    "Double": DoubleDataType,
    "Integer": IntegerDataType,
    "SmallInt": ShortDataType,
    "Pointer": PointerDataType,
    "Char": CharDataType,
    "UInt64": UnsignedIntegerDataType,
    "Byte": ByteDataType,
    "string": lambda: PointerDataType(CharDataType()),  # not StringDataType since it is a factory datatype
    # "WideString",
    # 'Extended',
    # 'AnsiString',
    # 'Int64',
    # 'Comp',
    # 'Variant',
    # 'Cardinal',
    # 'Single'
}

##########################################################################
#    PRINTING'n'LOGGING                                                  #
##########################################################################
def detail(msg: str) -> None:
    """
        Print a detailed debug message if VERBOSE_DETAIL is True.
        
        Parameters:
            msg (str): The debug message to print.
    """
    if VERBOSE_DETAIL:
        print(f"[DETAIL] {msg}")


def debug(msg: str) -> None:
    """
        Print a debug message if VERBOSE_DEBUG is True.
        
        Parameters:
            msg (str): The debug message to print.
    """
    if VERBOSE_DEBUG:
        print(f"[DEBUG] {msg}")


def info(msg: str) -> None:
    """
        Print an informative message if VERBOSE_INFO is True.
        
        Parameters:
            msg (str): The debug message to print.
    """
    if VERBOSE_INFO:
        print(f"[INFO] {msg}")


def warning(msg: str) -> None:
    """
        Print a warning message if VERBOSE_WARNING is True.
        
        Parameters:
            msg (str): The debug message to print.
    """
    if VERBOSE_WARNING:
        print(f"[WARNING] {msg}")


def printGeneralInformation() -> int:
    """
        Print some general meta data messages if GENERALINFORMATION is True.
        
        Parameters:
            originalFunctionCount (int): Number of functions as counted by ghidra's API pre-execution
    """
    # grab FunctionManager
    functionManager = currentProgram.getFunctionManager()

    # currentProgram is the built-in variable that points to Program class
    print(f"|> PRINTING GENERAL INFORMATION FOR PROGRAM: {currentProgram.getName()}") 
    print(f"|> Believed compiler: {currentProgram.getCompiler()}")
    # currentProgram.getLanguage() could be interesting instead of the following:
    print(f"|> Believed ptr size: {currentProgram.getDefaultPointerSize()}")
    print(f"|> Executable format: {currentProgram.getExecutableFormat()}")
    originalFunctionCount = functionManager.getFunctionCount()
    print(f"|> Total number of funcs: {originalFunctionCount}")
    print(f"|> Image base addr: {currentProgram.getImageBase()}")
    return originalFunctionCount


##########################################################################
#    HELPER FUNCTIONS                                                    #
##########################################################################
def readPointer(addr: Address, ptr_size: int) -> Address:
    """
    Read a pointer of the given size from memory at the specified address.

    Parameters:
        addr (ghidra.program.model.address.Address): The memory address to read from.
        ptr_size (int): The size of the pointer (4 or 8 bytes).

    Returns:
        ghidra.program.model.address.Address: The resolved address the pointer refers to.
    """
    memory = currentProgram.getMemory()
    return toAddr(memory.getInt(addr)) if ptr_size == 4 else toAddr(memory.getLong(addr))


def readPascalString(addr: Address) -> tuple[str, int]:
    """
    Read a Pascal-String from memory at the specified address.
    
    The string format expects the first byte to contain the length, 
    followed by the corresponding number of characters.

    Parameters:
        addr (ghidra.program.model.address.Address): The memory address where the Pascal-String starts.

    Returns:
        tuple[str, int]: The decoded string and its total byte length (including length byte).
    """
    # get memory interface
    memory = currentProgram.getMemory()
    
    # first byte of a PascalString denotes the number of upcoming chars
    pascalStringLen = memory.getByte(addr) & 0xFF

    # the first char starts at the second byte
    firstCharAddr = addr.add(1)
    # for storing the actual character information
    pascalString = ""

    # iterate over the following bytes to fill the PascalString
    for i in range(pascalStringLen):
        pascalString += chr(memory.getByte(firstCharAddr.add(i)) & 0xFF)

    return pascalString, pascalStringLen+1


##########################################################################
#    INITIALIZATION                                                      #
##########################################################################
def getArchitectureSettings() -> dict:
    """
    Return a dictionary with architecture-specific settings, including pointer size, architecture specific jump distances to MDT and RTTI_Class.
    
    The text block start and end addresses are just place holders at initialization time.

    Returns:
        dict: A dictionary containing architecture settings.
    """
    # Determine address size (4 or 8 bytes) depending on architecture
    ptrSize = currentProgram.getDefaultPointerSize()

    # Set architecture specific fixed size jumps and offsets accordingly
    # 32-bit case
    if ptrSize == 4:
        settings = {
            "ptrSize": ptrSize,
            "jumpDist": 88,
            "mdtOffset": 24,
            "rttiOffset": 16,
            "textBlockStartAddr": None,  # will be set later
            "textBlockEndAddr": None  # will be set later
        }
    # 64-bit case
    elif ptrSize == 8:
        settings = {
            "ptrSize": ptrSize,
            "jumpDist": 200,
            "mdtOffset": 48,
            "rttiOffset": 32,
            "textBlockStartAddr": None,  # will be set later
            "textBlockEndAddr": None  # will be set later
        }
    else:
        raise Exception("Unsupported pointer size")
    
    return settings


def getTextSection(memory: Memory) -> MemoryBlock:
    """
    Retrieve the '.text' memory block from the given memory object.

    Parameters:
        memory (ghidra.program.model.mem.Memory): The memory interface to search.

    Returns:
        ghidra.program.model.mem.memoryblock: The '.text' memory block.

    Raises:
        Exception: If the '.text' segment is not found.
    """
    for section in memory.getBlocks():
        if section.getName() == ".text":
            return section
    raise Exception(".text segment not found")


##########################################################################
#    MAIN LOGIC - VMT RELATED                                            #
##########################################################################
def checkVmtCandidate(candidate: Address, nextStruct: Address, settings: dict) -> bool:
    """
    Perform several sanity checks on the candidate VMT.

    Five fields of the VMT have been chosen for the sanity checks; three of which must always be filled with valid addresses in the range of the .text section. Two of which must be as well - or alternatively be NULL. As yet another sanity check, the address of the MDT must be larger than the address of its VMT.

    Parameters:
        candidate (ghidra.program.model.address.Address): The candidate VMT's address to be sanity-checked.
        nextStruct (ghidra.program.model.address.Address): The value of the VMT's NextStruct field, used for a sanity check.
        settings (dict): Architecture-specific settings including pointer size, jump distance, and start/end addresses of the .text block.
        
    Returns:
        bool: Result of candidate VMT sanity checks.
    """
    # for readability
    ptrSize = settings["ptrSize"]

    # store addresses of the VMT to be sanity checked
    addresses = []
    
    # NextStruct field
    addresses.append(nextStruct)
    
    # MDT
    mdtAddr = candidate.add(ptrSize * 6)
    mdt = readPointer(mdtAddr, ptrSize)
    if mdt:
        addresses.append(mdt)
        # it has been observed that MDTs are always located at higher addresses than their corresponding VMTs
        if mdt <= candidate:
            return False
        
    # sanity check for all 10 mandatory functions at the end of the VMT in a loop
    for currentFieldNumber in range(11, 22):
        # exclude the optional SafeCallExceptionMethod field since it is optional
        if currentFieldNumber != 14:
            currentField = candidate.add(ptrSize * currentFieldNumber)
            addresses.append(readPointer(currentField, ptrSize))

    # check if all grabbed non-NULL address are within range of the .text section
    return all(settings["textBlockStartAddr"] <= addr < settings["textBlockEndAddr"].subtract(settings["ptrSize"]) for addr in addresses)


def findVmts(settings: dict) -> list:
    """
    Scan the .text section for potential VMT addresses.
    
    Uses a sliding window approach based on pointer size and jump distance to identify forward references that may indicate the presence of a VMT. Applies basic sanity checks before accepting each candidate.

    Parameters:
        settings (dict): Architecture-specific settings including pointer size, jump distance,
                        and start/end addresses of the .text block.

    Returns:
        list[Address]: A list of addresses likely representing VMTs.
    """

    # if constants are set, this manipulates the analysed address range, instead of analysing the entire .text section
    if STARTADDR:
        settings["textBlockStartAddr"] = settings["textBlockStartAddr"].getAddress(STARTADDR)
    if ENDADDR:
        settings["textBlockEndAddr"] = settings["textBlockEndAddr"].getAddress(ENDADDR)
    
    textBlockSize = settings["textBlockEndAddr"].subtract(settings["textBlockStartAddr"])
    
    # empty list to be filled with vmt addresses
    vmtAddresses = []
    currentAddr = settings["textBlockStartAddr"]

    # iterate over the .text section, 4 or 8 byte data sliding window approach (architecture dependant)
    while currentAddr < settings["textBlockEndAddr"].subtract(settings["ptrSize"] - 1):
        # read value at current position depending on architecture size
        currentValue = readPointer(currentAddr, settings["ptrSize"])
        # detail(f"Reading {settings["ptrSize"]} bytes @ {currentAddr} yielded: {currentValue}")
        
        # calculate the displacement between two addresses (this - addr)
        distance = currentValue.subtract(currentAddr)
        # necessary but not sufficient conditional for identifying VMTs
        if distance == settings["jumpDist"]:
            debug(f"Found forward reference of {settings['jumpDist']} bytes -> potential VMT found @ {currentAddr}")
            
            # although not quite a sufficient conditional for VMT identification, it still gets rid of a lot of false positives by performing several sanity checks
            if not checkVmtCandidate(currentAddr, currentValue, settings):
                debug(f"REJECTED VMT candidate @ {currentAddr}. Didn't pass sanity checks.")
                currentAddr = currentAddr.add(1)
                continue
            
            # store the VMT's address for return
            vmtAddresses.append(currentAddr)
            debug(f"VMT @ {currentAddr} passed first sanity checks. Adding it to the list of VMTs.")
        
        # forward step
        currentAddr = currentAddr.add(1)
        
        # since this function takes the longest amount of time, give an amateur progress bar
        if VERBOSE_INFO:
            progress = currentAddr.subtract(settings["textBlockStartAddr"])
            if progress % 100000 == 0:
                info(f"[1/8] Processed {round((progress/textBlockSize)*100)}% addresses in .text section.") 

    return vmtAddresses


def getVmtFieldAddresses(vmtAddresses: list, settings: dict, fieldname: str) -> dict:
    """
    Resolve the addresses of specific VMT fields and validate their targets.
    
    For each VMT address, this function computes the address of the requested field (e.g., MDT or RTTI), dereferences it, and adds it to a returned dict.

    Parameters:
        vmtAddresses (list[Address]): List of candidate VMT addresses.
        settings (dict): Architecture-specific settings including offsets and .text boundaries.
        fieldname (str): Key indicating which field to extract (e.g., 'mdtOffset', 'rttiOffset').

    Returns:
        dict[Address, Address]: Mapping from VMT address to the resolved field address.
    """
    # empty dictionary for return information
    vmtFieldRelations = {}

    for vmtAddr in vmtAddresses:    
        # compute address where the field's pointer lies
        fieldAddress = vmtAddr.add(settings[f"{fieldname}"])
        debug(f"Pointer to { {'mdtOffset': 'MDT', 'rttiOffset': 'VmtRtti'}.get(fieldname, 'UNKNOWN') } @ {fieldAddress}")
        
        # get dereferenced value of pointer
        try:
            fieldValue = readPointer(fieldAddress, settings["ptrSize"])
        except MemoryAccessException:
            warning(f"Could not read bytes @ {fieldAddress}. Skipping.")
            continue

        # prepare information for return
        vmtFieldRelations[vmtAddr] = fieldValue
        
    return vmtFieldRelations


##########################################################################
#    MAIN LOGIC - MDT RELATED                                            #
##########################################################################
def traverseMdtTopLevel(vmtMdtRelations: dict, settings: dict) -> dict:
    """
    Traverse the top-level structure of MDTs corresponding to a list of VMTs.
    
    Reads the number of method entry references from each MDT and resolves the addresses of the corresponding method entries. The result includes a mapping from VMTs to their MDT and a list of associated method entry addresses.

    Parameters:
        vmtMdtRelations (dict): Mapping of VMT addresses to their MDT addresses.
        settings (dict): Architecture-specific settings including pointer size.

    Returns:
        dict: A dictionary mapping each VMT address to a nested dictionary with its MDT address and a list of resolved method entry addresses.
    """
    # regrab memory interface
    memory = currentProgram.getMemory()

    vmtMdtTopInfo = {}

    for vmtAddr, mdtAddr in vmtMdtRelations.items():
        # store address information for this MDT traversal
        vmtMdtTopInfo[vmtAddr] = {"mdt": mdtAddr, "methodEntries": []}

        # navigate to the NumOfMethodEntryRefs field
        numOfMethodEntryRefsAddr = mdtAddr.add(2)
        # grab its 2B long content (architecture-independant)
        numOfMethodEntryRefs = memory.getShort(numOfMethodEntryRefsAddr)
        debug(f"NumOfMethodEntryRefs: {numOfMethodEntryRefs} for MDT @ {mdtAddr}")

        if numOfMethodEntryRefs == 0:
            continue

        # go to start of MethodEntryRef concatenation
        methodEntryRefStartAddr = numOfMethodEntryRefsAddr.add(2)

        # get all starting addresses of the MDT's MethodEntries (`AddressOfMethodEntry`) and add them to a list
        methodEntryAddresses = []
        for i in range(numOfMethodEntryRefs):
            methodEntryRefAddr = methodEntryRefStartAddr.add(i * (settings["ptrSize"] + 4))
            try:
                methodEntryAddr = readPointer(methodEntryRefAddr, settings["ptrSize"])
            except MemoryAccessException:
                warning(f"Could not read bytes @ {methodEntryRefAddr}. Skipping.")
                continue
            
            methodEntryAddresses.append(methodEntryAddr)

        # add address information of found methodEntries to correlated MDT / VMT information
        vmtMdtTopInfo[vmtAddr]["methodEntries"].extend(methodEntryAddresses)

    debug(f"Dictionary information after traverseMdtTopLevel(): {vmtMdtTopInfo}")
    return vmtMdtTopInfo


def traverseParamEntries(firstParamEntryAddr: Address, numOfParamEntries: int, settings: dict):
    """
    Traverse a sequence of ParamEntries and extract relevant RTTI and naming information.
    
    For each ParamEntry, this function reads and dereferences the RTTI address, resolves its
    namespace (if available), reads the associated Pascal-style parameter name, and collects
    the information in a structured dictionary.

    Parameters:
        firstParamEntryAddr (ghidra.program.model.address.Address): Starting address of the first ParamEntry.
        numOfParamEntries (int): Number of ParamEntries to process.
        settings (dict): Architecture-specific settings including pointer size.

    Returns:
        dict: Mapping from each ParamEntry's address to a dictionary containing the parameter's RTTI address, name, and namespace.
    """
    paramEntriesInfo = {}
    currentAddr = firstParamEntryAddr
    for i in range(numOfParamEntries):
        # cache addr at which each ParamEntry starts (as a key for storing information below) 
        paramEntryAddr = currentAddr
        
        # get addr of RTTI object (indirect reference hence dereference)
        try:
            rtti = readPointer(readPointer(currentAddr, settings["ptrSize"]), settings["ptrSize"])
            rttiNamespace = traverseRttiObject(rtti, settings)
        except Exception:
            rtti = None
            rttiNamespace = None

        # go to NameOfRtti field
        currentAddr = currentAddr.add(settings["ptrSize"] + 2)
        # grab name and size information
        paramName, strLen = readPascalString(currentAddr)
        
        # go to AddrOfRtti field of next ParamEntry (remark: 3 bytes of additional data for numOfParamEntries > 1)
        currentAddr = currentAddr.add(strLen + 3)
        
        # store data in a senseful way
        paramEntriesInfo[paramEntryAddr] = {"AddrOfRtti": rtti, "ParamName": paramName, "rttiNamespace": rttiNamespace}
    
    return paramEntriesInfo


def traverseMethodEntries(vmtMdtTopInfo: dict, settings: dict) -> dict:
    """
    Traverse all MethodEntries associated with each VMT's MDT and collect detailed metadata.
    
    For each MethodEntry, this function extracts the function entry point, its name, return type RTTI information, and associated parameter entries. If any critical part cannot be dereferenced or lies outside of the executable section, the corresponding VMT is discarded from the final result.

    Parameters:
        vmtMdtTopInfo (dict): Mapping from VMT address to top-level MDT metadata.
        settings (dict): Architecture-specific settings including pointer size and memory bounds.

    Returns:
        dict: Updated mapping including enriched MethodEntry information per VMT.
    """
    # regrab memory interface
    memory = currentProgram.getMemory()

    # the zero-address for reusability
    allZeroAddress = toAddr("0x0")

    # iterate over all MethodEntries of each VMT's MDT; by creating a new list, we can change the size of the underlying dictionary during runtime 
    for vmt in list(vmtMdtTopInfo.keys()):
        # store information about relevant fields for each MethodEntry of an MDT
        methodEntriesInfo = {}

        for methodEntry in vmtMdtTopInfo[vmt]["methodEntries"]:
            # dictionary to hold relevant information for a single MethodEntry 
            methodEntryInfo = {}

            # grab entry point of the MethodEntry's function definition 
            try:
                functionDefinitionAddr = methodEntry.add(2)
            except AddressOutOfBoundsException:
                # this error can happen when a huge concatenation of addresses structure is falsely detected as a VMT, hence, ignore its method entries 
                break
            try:
                methodEntryInfo["functionEntryPoint"] = readPointer(functionDefinitionAddr, settings["ptrSize"])
            except MemoryAccessException:
                warning(f"Could not read bytes @ {functionDefinitionAddr}. Skipping methodEntry: {methodEntry}.")
                continue

            # grab the corresponding function name
            nameOfFunctionAddr = functionDefinitionAddr.add(settings["ptrSize"])
            try:
                methodEntryInfo["nameOfFunction"], strLen = readPascalString(nameOfFunctionAddr)
            except MemoryAccessException:
                warning(f"Couldn't grab nameOfFunctionAddr: {nameOfFunctionAddr}. Skipping methodEntry: {methodEntry}.")
                continue
            
            # grab information about return type's RTTI class
            returnTypeAddress = nameOfFunctionAddr.add(strLen + 2)
            try:
                dereferencedReturnTypeAddress = readPointer(returnTypeAddress, settings["ptrSize"])
                # if all zero'd, void is the return type
                if dereferencedReturnTypeAddress == allZeroAddress:
                    methodEntryInfo["returnTypeRttiAt"] = "n.a."
                    methodEntryInfo["returnTypeStr"] = "void"
                    detail(f"void return type applied for returnTypeAddress: {returnTypeAddress}")
                else:
                    methodEntryInfo["returnTypeRttiAt"] = dereferencedReturnTypeAddress
                    doubleDereferencedReturnTypeAddress = readPointer(dereferencedReturnTypeAddress, settings["ptrSize"])
                    methodEntryInfo["returnTypeStr"] = traverseRttiObject(doubleDereferencedReturnTypeAddress, settings)
            except MemoryAccessException:
                warning(f"Could not read bytes @ {returnTypeAddress}. Skipping.")
                continue
            
            # get NumOfParamEntries
            numOfParamEntriesAddr = returnTypeAddress.add(settings["ptrSize"] + 2)
            numOfParamEntries = memory.getByte(numOfParamEntriesAddr) & 0xFF

            # go to first ParamEntry substructure
            firstParamEntryAddr = numOfParamEntriesAddr.add(2)
            
            # sanity check for the ParamEntries: check if potential ParamEntries are within .text section
            if not (settings["textBlockStartAddr"] <= firstParamEntryAddr <= settings["textBlockEndAddr"]):
                # addresses outside the .text section mean false positive ParamEntries, hence remove them 
                del vmtMdtTopInfo[vmt]
                break

            # get information about position and names of the specific MethodEntry's parameters
            methodEntryInfo["paramEntries"] = traverseParamEntries(firstParamEntryAddr, numOfParamEntries, settings)
            
            # store information to the dictionary holding data for all MethodEntries of an MDT 
            methodEntriesInfo[methodEntry] = methodEntryInfo

        # the else clause only triggers, if the inner loops break didn't trigger
        else: 
            # store information to the dictionary holding all data
            vmtMdtTopInfo[vmt]["methodEntriesInfo"] = methodEntriesInfo

    debug(f"Dictionary information after traverseMethodEntries(): {vmtMdtTopInfo}")
    return vmtMdtTopInfo


##########################################################################
#    MAIN LOGIC - RTTI_CLASS RELATED                                     #
##########################################################################
def traverseRttiObject(addr: Address, settings: dict) -> str | None:
    """
    Traverse a Delphi RTTI object and extract string information based on its magic byte.
    If the RTTI object is an RTTI_Class (0x07), its object name and namespace get returned, i.e. `Namespace.ClassName`.
    If the RTTI object is of any other RTTI object type, only the object's name gets returned, as the structure of the different RTTI object types have not yet been fully understood.

    Parameters:
        addr (ghidra.program.model.address.Address): The address pointing to the beginning of a potential RTTI object.
        settings (dict): Architecture-specific settings including pointer size.

    Returns:
        str | None: Namespace of the RTTI_Class's VMT as a string, or the the RTTI object's name (if it's not an RTTI_Class), or None if the structure is invalid.
    """
    # regrab memory interface
    memory = currentProgram.getMemory()
    magicByte = memory.getByte(addr) & 0xFF

    if magicByte > 0x15:
        warning(f"Tried to traverse data @ {addr}, but it's not an RTTI object! Skipping traversal.")
        return None
    
    # go to RttiObjectName field
    rttiObjectNameAddr = addr.add(1)
    # read Pascal String to get name of the RTTI object
    rttiObjectName, strLen = readPascalString(rttiObjectNameAddr)

    # if the traversed object is not of type RTTI_Class, only return its name as information
    if magicByte != 0x07:
        return rttiObjectName

    # go to RttiNamespace field
    rttiNamespaceAddr = rttiObjectNameAddr.add(strLen + settings["ptrSize"] * 2 + 2)
    # read Pascal String to get the namespace of the RTTI_Class
    rttiNamespace, _ = readPascalString(rttiNamespaceAddr)

    # construct namespace from the PoV of a function in Delphi style (not yet C++!)
    namespace = rttiNamespace + "." + rttiObjectName
    
    return namespace


def addNamespaceInformation(vmtRttiRelations: dict, symbolInfo: dict, settings: dict) -> dict:
    """
    Augment symbol information with the namespace string derived via RTTI traversal. It ensures consistency with any VMTs previously filtered out.

    Parameters:
        vmtRttiRelations (dict): Mapping of VMT addresses to RTTI addresses.
        symbolInfo (dict): Dictionary holding previously gathered metadata.
        settings (dict): Architecture-specific configuration settings.

    Returns:
        dict: Updated symbolInfo dictionary with added `namespace` fields.
    """
    for vmt, rtti in vmtRttiRelations.items():
        # if during traverseMethodEntries() a vmt had been removed, take this change into effect here as well
        if vmt not in symbolInfo:
            continue

        namespace = traverseRttiObject(rtti, settings)
        debug(f"Mapping namespace information {namespace} to vmt @ {vmt}")
        symbolInfo[vmt]["namespace"] = namespace

    debug(f"Final dictionary information: {symbolInfo}")
    return symbolInfo


##########################################################################
#    MAIN LOGIC - TRANSFORMATION FUNCTIONS                               #
##########################################################################
def prepareNamespace(namespaceStr: str) -> Namespace:
    """
    Create or retrieve a nested namespace hierarchy in Ghidra's symbol table from a namespace string.

    Given a VMT address and a dot-separated namespace string, this function iteratively creates or retrieves each namespace component as a child of the previous one, starting from the global namespace. The "youngest" namespace object is returned.

    Parameters:
        namespaceStr (str): Dot-separated namespace string (e.g., "MyNamespace.SubNamespace.ClassName").

    Returns:
        ghidra.program.model.symbol.Namespace: The final Namespace object corresponding to the deepest namespace level.
    """
    # grab ghidra's symbol table
    symbolTable = currentProgram.getSymbolTable()
    # split the namespace string at the first '.' character, returning a list of its parts
    namespaceParts = namespaceStr.split('.')

    # start from the root namespace and iteratively grab or create its children
    parentNamespace = currentProgram.getGlobalNamespace()
    for part in namespaceParts:
        # look for an existing namespace with this name under the current parent or create it if needed
        # remark: USER_DEFINED makes sure that later on, the information will not be overwritten by ghidra
        try:
            parentNamespace = symbolTable.getOrCreateNameSpace(parentNamespace, part, SourceType.USER_DEFINED)
        except InvalidInputException:
            return None
    
    # return the final namespace object (e.g., TApplication)    
    return parentNamespace



def prepareDataType(typeString: str) -> DataType:
    """
    Returns the datatype concerning a string argument - either by mapping to a ghidra built-in datatype or by building the namespace of the RTTI type.

    Parameters:
        typeString (str): A string representing the datatype which shall be returned accordingly.
        
    Returns:
        DataType: The datatype object, either built by a constructor or a ghidra built-in datatype.
    """
    dataTypes = currentProgram.getDataTypeManager()

    # the following three lines are currently used for debugging purposes only
    global dataTypeMapping
    if "." not in typeString:
        types.add(typeString)

    if typeString in dataTypeMapping:
        # return mapped ghidra built-in datatype if it's a simple datatype
        finalDataType = dataTypeMapping[typeString]()
    else:
        # define the class name and namespace
        paramNamespace = prepareNamespace(typeString)
        paramClassName = typeString.split('.')[-1].rstrip(">")
        
        # create a class in the given namespace via the light-weight FlatProgramAPI function
        try:
            createClass(paramNamespace, paramClassName)
        except DuplicateNameException:
            pass

        # create a categorypath and the actual datatype
        categoryPath = CategoryPath("/" + paramNamespace.getParentNamespace().getName(True).replace("::", "/"))  # → /Vcl/Forms
        dataType = StructureDataType(categoryPath, paramClassName, 0)

        # register the datatype with the DataTypeManager
        registeredDataType = dataTypes.addDataType(dataType, None)

        # create a pointer to the class (Delphi typically passes/returns class instances as pointers) and return it
        finalDataType = PointerDataType(registeredDataType)

    return finalDataType


def applySymbols(allSymbolInfo: dict, settings: dict) -> dict:
    """
    Handles the actual symbol name recovering, given all previously gathered information.

    For every found VMT, the function iterates over the MethodEntry data and attempts to apply data like its name, parameter and return types and parameter names.

    Parameters:
        allSymbolInfo (dict): Dictionary holding previously gathered metadata.
        settings (dict): Architecture-specific settings including pointer size, jump distance, and start/end addresses of the .text block.
        
    Returns:
        dict: Counts the numbers of VMTs, function names, and FQNs which have been fully recovered.
    """
    # grab necessary interfaces
    functionManager = currentProgram.getFunctionManager()

    # count how many VMT/functions have been fully recovered (evaluation information only)
    applyCount = {"vmt": 0, "function": 0, "fqn": 0, "return": 0, "paramSet": 0}

    for vmt, topLevelValue in allSymbolInfo.items():
        detail(f"[7/8] Currently proceessing symbol information for VMT @ {vmt} ...")
        applyCount["vmt"] += 1

        # get namespace information from ghidra's symbol table or create it if required
        if "namespace" not in topLevelValue.keys():
            continue
        nameSpaceStr = topLevelValue["namespace"]
        if nameSpaceStr is None:
            continue
        namespace = prepareNamespace(nameSpaceStr)

        for secondLevelValue in topLevelValue["methodEntriesInfo"].values():
            # grab all pieces of information from all MDT levels and recover symbols accordingly
            functionEntryPoint = secondLevelValue["functionEntryPoint"]
            functionName = secondLevelValue["nameOfFunction"]
            returnTypeStr = secondLevelValue["returnTypeStr"]
            paramTuples = []
            for paramEntry, thirdLevelValue in secondLevelValue["paramEntries"].items():
                if thirdLevelValue["rttiNamespace"] is None or thirdLevelValue["ParamName"] == "Self":
                    paramTuples.append((thirdLevelValue["ParamName"], nameSpaceStr))
                    continue
                paramTuples.append((thirdLevelValue["ParamName"], thirdLevelValue["rttiNamespace"]))
            

            # -------------------------- APPLY FUNCTION NAMES ----------------------------------- #
            # start the actual symbol name recovery transformation with grabbing the function to edit
            function = functionManager.getFunctionAt(functionEntryPoint)
            # if ghidra doesn't recognize this address already as a function 
            if not function:
                # creating via the light-weight FlatProgramAPI function sets a name automatically
                function = createFunction(functionEntryPoint, functionName)
                # function could not be created for some reason, hence skip its symbol recovery
                if function is None:
                    continue
            else:
                # if function is already been known to ghidra, replace its name
                function.setName(functionName, SourceType.USER_DEFINED)
            
            applyCount["function"] += 1
            # ----------------------------------------------------------------------------------- #


            # -------------------------- APPLY NAMESPACES --------------------------------------- #
            if namespace is not None:
                try:
                    function.setParentNamespace(namespace)
                    detail(f"Successfully applied FQN {namespace}::{functionName} function @ {functionEntryPoint}.")
                    applyCount["fqn"] += 1
                except Exception as e:  # java.lang.IllegalArgumentException: namespace is from different program instance: System::TMarshal
                    warning(e)
                    warning(namespace)
                    pass
            # ----------------------------------------------------------------------------------- #


            # -------------------------- APPLY RETURN TYPES ------------------------------------- #
            if returnTypeStr is not None:
                # retrieve DataType object for return type application
                finalDataType = prepareDataType(returnTypeStr)

                # replace return type
                function.setReturnType(finalDataType, SourceType.USER_DEFINED)

                detail(f"Successfully applied return type {returnTypeStr} to function @ {functionEntryPoint}.")
                applyCount["return"] += 1
            # ----------------------------------------------------------------------------------- #


            # -------------------------- APPLY PARAM TUPLES ------------------------------------- #
            params = []
            for paramName, rttiName in paramTuples:
                # retrieve DataType object for parameter application preparation
                finalDataType = prepareDataType(rttiName)
                
                # Create parameters using ParameterImpl(name, dataType, program) and add them to 
                param = ParameterImpl(paramName, finalDataType, currentProgram)
                params.append(param)

            # replace parameters
            try:
                function.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    params
                )
            # skip in case of invalid symbol names
            except InvalidInputException:
                continue
            
            applyCount["paramSet"] += 1
            # ----------------------------------------------------------------------------------- #

    return applyCount


##########################################################################
#    MAIN LOGIC - ACTUAL MAIN                                            #
##########################################################################
def main() -> None:
    """
    Main function orchestrating the analysis and recovery of symbol and RTTI information from an executable's VMTs and MDTs within Ghidra.
    """
    # print general information and retrieve pre-execution function count
    originalFunctionCount = printGeneralInformation()

    # for statistical logging in the end
    totalFunctions = currentProgram.getFunctionManager().getFunctionCount()

    # grab relevant numbers which depend on the architecture of the executable
    settings = getArchitectureSettings()

    # get memory interface of executable (beware: "memory changes should generally be completed prior to analysis.")
    memory = currentProgram.getMemory()
    textSection = getTextSection(memory)
    settings.textBlockStartAddr = textSection.getStart()
    settings.textBlockEndAddr = textSection.getEnd()

    # print more general information
    print(f"|> Size of .text section: {textSection.getSizeAsBigInteger()}")

    info("[1/8] Starting to scan for candidate VMTs & performing sanity checks...")
    vmtAddresses = findVmts(settings)

    # using the found VMT addresses, for each VMT, grab its corresponding MDT
    info("[2/8] Grabbing the MDT of every found VMT...")
    vmtMdtRelations = getVmtFieldAddresses(vmtAddresses, settings, "mdtOffset")

    # using the found VMT addresses, for each VMT, grab its corresponding RTTI
    info("[3/8] Grabbing the RTTI_Class of every found VMT...")
    vmtRttiRelations = getVmtFieldAddresses(vmtAddresses, settings, "rttiOffset")

    # find all starting addresses of all MethodEntry substructures of every MDT
    # the result is structured as follows: {<vmtAddr>: {"mdt": <mdtAddress>, "methodEntries": [<methodEntry1Addr>, <methodEntry2Addr>, ...]}}
    info("[4/8] Grabbing the MethodEntries of every found MDT...")
    vmtMdtTopInfo = traverseMdtTopLevel(vmtMdtRelations, settings)

    # entlang der MDT Struktur entlang hangeln, um relevante Daten zu erhalten.
    info("[5/8] Extracting information of all MethodEntries of every found MDT...")
    vmtMdtSymbolInfo = traverseMethodEntries(vmtMdtTopInfo, settings)
    
    # complete symbol recovery information by calling traverseRttiClass(addr, settings) for all VMTs 
    info("[6/8] Extracting the RTTI namespaces for every VMT/MDT...")
    allSymbolInfo = addNamespaceInformation(vmtRttiRelations, vmtMdtSymbolInfo, settings)
    
    # apply symbol name recovery
    info("[7/8] Reconstructing all symbol names...")
    recCounts = applySymbols(allSymbolInfo, settings)

    # print final statistics
    totalFunctions = currentProgram.getFunctionManager().getFunctionCount()
    info(f"[8/8] Statistics: Pre-execution number of functions: {originalFunctionCount}")
    info(f"[8/8] Statistics: Post-execution number of functions: {totalFunctions}")
    info(f"[8/8] Statistics: Number of VMTs found: {len(vmtAddresses)}")
    info(f"[8/8] Statistics: Number of symbol recovered VMTs: {recCounts['vmt']}, yielding {recCounts['vmt']/len(vmtAddresses)*100:.2f}% of all found VMTs.")
    info(f"[8/8] Statistics: Number of symbol recovered functions: {recCounts['function']}, yielding {recCounts['function']/totalFunctions*100:.2f}% of all functions; or {recCounts['function']/originalFunctionCount*100:.2f}% when using pre-execution function count.")
    info(f"[8/8] Statistics: Number of applied FQNs: {recCounts['fqn']}, yielding {recCounts['fqn']/totalFunctions*100:.2f}% of all functions; or {recCounts['fqn']/originalFunctionCount*100:.2f}% when using pre-execution function count.")
    info(f"[8/8] Statistics: Number of applied return types: {recCounts['return']}, yielding {recCounts['return']/totalFunctions*100:.2f}% of all functions; or {recCounts['return']/originalFunctionCount*100:.2f}% when using pre-execution function count.")
    info(f"[8/8] Statistics: Number of applied parameter sets: {recCounts['paramSet']}, yielding {recCounts['paramSet']/totalFunctions*100:.2f}% of all functions; or {recCounts['paramSet']/originalFunctionCount*100:.2f}% when using pre-execution function count.")
    info("[8/8] Finished.")
    
    # the following two lines are for debugging purposes only
    global types
    debug(types)

if __name__ == "__main__":
    main()

