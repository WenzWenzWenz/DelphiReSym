# A Delphi symbol name recovery tool. Uses after-compilation metadata to reconstruct symbols of
# function signatures.
# @author Lukas Wenz - https://github.com/WenzWenzWenz
# @category Delphi
# @keybinding
# @menupath
# @toolbar
# @runtime PyGhidra
# -*- coding: utf-8 -*-
"""
A Delphi symbol name recovery tool. Uses after-compilation metadata to reconstruct symbols of
function signatures.
"""
from __future__ import annotations

import pyghidra

from typing import TYPE_CHECKING, cast, Optional, Any
from dataclasses import dataclass

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *                                        # type: ignore

from ghidra.program.model.data import *                                         # type: ignore

from ghidra.program.model.symbol import SourceType, Namespace                   # type: ignore
from ghidra.program.model.listing import ParameterImpl, Function, Program       # type: ignore
from ghidra.program.model.mem import MemoryAccessException, Memory, MemoryBlock # type: ignore
from ghidra.program.model.address import Address, AddressOutOfBoundsException   # type: ignore
from ghidra.util.task import TaskMonitor                                        # type: ignore
from ghidra.util.exception import InvalidInputException, DuplicateNameException # type: ignore
from ghidra.program.model.data import (                                         # type: ignore
    IntegerDataType,
    CharDataType,
    StructureDataType,
)

# this global variable is currently used for debugging purposes only
types = set()

if _g := globals():

    def convert_to_addr(x: Any) -> Address:
        return _g["toAddr"](x)

    currentProgram = cast(Program, _g["currentProgram"])
    monitor = cast(TaskMonitor, _g["monitor"])
else:
    raise RuntimeError("could not access ghidra scripting global variables")


class MonitorCancel(BaseException):
    """
    Raised when the user cancels the process via the monitor dialog.
    """


def check_cancel():
    if monitor.isCancelled():
        raise MonitorCancel


###################################################################################################
#    CONFIGS'n'CONSTANTS                                                                          #
###################################################################################################
# set whether or not to print detailed debug information to stdout
VERBOSE_DETAIL = False
# set whether or not to print detailed debug information to stdout
VERBOSE_DEBUG = False
# set whether or not to print less detailed debug information to stdout
VERBOSE_INFO = True
# set whether or not to print warning information to stdout
VERBOSE_WARNING = False

# set these variables to specific hexadecimal address strings to narrow the analysed address range,
# e.g.: STARTADDR = "005c12dc"
STARTADDR = None
ENDADDR = None

# TODO: work on: non exhaustive list of non-RTTI dependant types and make this feature toggleable
data_type_mapping = {
    "Boolean": BooleanDataType,
    "void": VoidDataType,
    "Double": DoubleDataType,
    "Integer": IntegerDataType,
    "SmallInt": ShortDataType,
    "Pointer": PointerDataType,
    "Char": CharDataType,
    "UInt64": UnsignedIntegerDataType,
    "Byte": ByteDataType,
    "string": lambda: PointerDataType(
        CharDataType()
    ),  # not StringDataType since it is a factory datatype
    # "WideString",
    # 'Extended',
    # 'AnsiString',
    # 'Int64',
    # 'Comp',
    # 'Variant',
    # 'Cardinal',
    # 'Single'
}


###################################################################################################
#    PRINTING'n'LOGGING                                                                           #
###################################################################################################
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


###################################################################################################
#    HELPER FUNCTIONS                                                                             #
###################################################################################################
def read_ptr(addr: Address, ptr_size: int) -> Address:
    """
    Read a pointer of the given size from memory at the specified address.

    Parameters:
        addr (ghidra.program.model.address.Address): The memory address to read from.
        ptr_size (int): The size of the pointer (4 or 8 bytes).

    Returns:
        ghidra.program.model.address.Address: The resolved address the pointer refers to.
    """
    memory = currentProgram.getMemory()
    return (
        convert_to_addr(memory.getInt(addr))
        if ptr_size == 4
        else convert_to_addr(memory.getLong(addr))
    )


def read_pascal_str(addr: Address) -> tuple[str, int]:
    """
    Read a Pascal-String from memory at the specified address.

    The string format expects the first byte to contain the length,
    followed by the corresponding number of characters.

    Parameters:
        addr (ghidra.program.model.address.Address): The memory address where the Pascal-String
            starts.

    Returns:
        tuple[str, int]: The decoded string and its total byte length (including length byte).
    """
    # get memory interface
    memory = currentProgram.getMemory()

    # first byte of a PascalString denotes the number of upcoming chars
    pascal_str_len = memory.getByte(addr) & 0xFF

    # the first char starts at the second byte
    first_char_addr = addr.add(1)
    # for storing the actual character information
    pascal_str = ""

    # iterate over the following bytes to fill the PascalString
    for i in range(pascal_str_len):
        pascal_str += chr(memory.getByte(first_char_addr.add(i)) & 0xFF)

    return pascal_str, pascal_str_len + 1


@dataclass
class ArchitectureSpecificSettings:
    ptr_size: int
    jump_dist: int
    text_block_start_addr: Optional[Address] = None
    text_block_end_addr: Optional[Address] = None

    @property
    def mdt_offset(self) -> int:
        return self.ptr_size * 6

    @property
    def rtti_offset(self) -> int:
        return self.ptr_size * 4


def get_architecture_settings() -> ArchitectureSpecificSettings:
    """
    Return a dictionary with architecture-specific settings, including pointer size, architecture
    specific jump distances to MDT and RTTI_Class.

    The text block start and end addresses are just place holders at initialization time.

    Returns:
        dict: A dictionary containing architecture settings.
    """
    ptr_size = currentProgram.getDefaultPointerSize()

    if ptr_size == 4:
        return ArchitectureSpecificSettings(ptr_size=4, jump_dist=88)
    if ptr_size == 8:
        return ArchitectureSpecificSettings(ptr_size=8, jump_dist=200)
    raise RuntimeError(f"Unsupported pointer size: {ptr_size}")


def get_text_section(memory: Memory) -> MemoryBlock:
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


###################################################################################################
#    MAIN LOGIC - VMT RELATED                                                                     #
###################################################################################################
def check_vmt_candidate(
    candidate: Address,
    next_struct: Address,
    settings: ArchitectureSpecificSettings,
) -> bool:
    """
    Perform several sanity checks on the candidate VMT.

    Five fields of the VMT have been chosen for the sanity checks; three of which must always be
    filled with valid addresses in the range of the .text section. Two of which must be as well - or
    alternatively be NULL. As yet another sanity check, the address of the MDT must be larger than
    the address of its VMT.

    Parameters:
        candidate (ghidra.program.model.address.Address): The candidate VMT's address to be
            sanity-checked.
        nextStruct (ghidra.program.model.address.Address): The value of the VMT's NextStruct field,
            used for a sanity check.
        settings (dict): Architecture-specific settings including pointer size, jump distance, and
            start/end addresses of the .text block.

    Returns:
        bool: Result of candidate VMT sanity checks.
    """
    ptr_size = settings.ptr_size
    addresses = []
    addresses.append(next_struct)
    mdt_addr = candidate.add(ptr_size * 6)
    mdt = read_ptr(mdt_addr, ptr_size)
    if mdt:
        addresses.append(mdt)
        # it has been observed that MDTs are always located at higher addresses than their
        # corresponding VMTs
        if mdt <= candidate:
            return False

    # sanity check for all 10 mandatory functions at the end of the VMT in a loop
    for current_field_number in range(11, 22):
        # exclude the optional SafeCallExceptionMethod field since it is optional
        if current_field_number != 14:
            current_field = candidate.add(ptr_size * current_field_number)
            addresses.append(read_ptr(current_field, ptr_size))

    # check if all grabbed non-NULL address are within range of the .text section
    return all(
        settings.text_block_start_addr
        <= addr
        < settings.text_block_end_addr.subtract(settings.ptr_size)
        for addr in addresses
    )


def find_vmts(settings: ArchitectureSpecificSettings) -> list:
    """
    Scan the .text section for potential VMT addresses.

    Uses a sliding window approach based on pointer size and jump distance to identify forward
    references that may indicate the presence of a VMT. Applies basic sanity checks before accepting
    each candidate.

    Parameters:
        settings (dict): Architecture-specific settings including pointer size, jump distance,
                        and start/end addresses of the .text block.

    Returns:
        list[Address]: A list of addresses likely representing VMTs.
    """

    # if constants are set, this manipulates the analysed address range, instead of analysing the
    # entire .text section
    if STARTADDR:
        settings.text_block_start_addr = settings.text_block_start_addr.getAddress(STARTADDR)
    if ENDADDR:
        settings.text_block_end_addr = settings.text_block_end_addr.getAddress(ENDADDR)

    text_block_size = settings.text_block_end_addr.subtract(settings.text_block_start_addr)

    # empty list to be filled with vmt addresses
    vmt_addresses = []
    current_address = settings.text_block_start_addr

    # iterate over the .text section, 4 or 8 byte data sliding window approach (architecture
    # dependant)
    while current_address < settings.text_block_end_addr.subtract(settings.ptr_size - 1):
        check_cancel()
        # read value at current position depending on architecture size
        current_val = read_ptr(current_address, settings.ptr_size)

        # calculate the displacement between two addresses (this - addr)
        distance = current_val.subtract(current_address)
        # necessary but not sufficient conditional for identifying VMTs
        if distance == settings.jump_dist:
            debug(
                f"Found forward reference of {settings.jump_dist} bytes -> "
                f"potential VMT found @ {current_address}"
            )

            # although not quite a sufficient conditional for VMT identification, it still gets rid
            # of a lot of false positives by performing several sanity checks
            if not check_vmt_candidate(current_address, current_val, settings):
                debug(f"REJECTED VMT candidate @ {current_address}. Didn't pass sanity checks.")
                current_address = current_address.add(1)
                continue

            # store the VMT's address for return
            vmt_addresses.append(current_address)
            debug(
                f"VMT @ {current_address} passed first sanity checks. Adding it to the list of "
                "VMTs."
            )

        # forward step
        current_address = current_address.add(1)

        # since this function takes the longest amount of time, give an amateur progress bar
        if VERBOSE_INFO:
            progress = current_address.subtract(settings.text_block_start_addr)
            if progress % 100000 == 0:
                info(
                    f"[1/8] Processed {round((progress/text_block_size)*100)}% addresses in .text "
                    "section."
                )

    return vmt_addresses


def get_vmt_field_addresses(
    vmt_addresses: list[Address],
    settings: ArchitectureSpecificSettings,
    offset: int,
    debug_name: str,
) -> dict:
    """
    Resolve the addresses of specific VMT fields and validate their targets.

    For each VMT address, this function computes the address of the requested field (e.g., MDT or
    RTTI), dereferences it, and adds it to a returned dict.

    Parameters:
        vmtAddresses (list[Address]): List of candidate VMT addresses.
        settings (dict): Architecture-specific settings including offsets and .text boundaries.
        fieldname (str): Key indicating which field to extract (e.g., 'mdtOffset', 'rttiOffset').

    Returns:
        dict[Address, Address]: Mapping from VMT address to the resolved field address.
    """
    vmt_field_addresses = {}

    for vmt_addr in vmt_addresses:
        check_cancel()
        # compute address where the field's pointer lies
        field_addr = vmt_addr.add(offset)
        debug(f"Pointer to {debug_name} @ {field_addr}")
        try:
            field_val = read_ptr(field_addr, settings.ptr_size)
        except MemoryAccessException:
            warning(f"Could not read bytes @ {field_addr}. Skipping.")
            continue
        vmt_field_addresses[vmt_addr] = field_val

    return vmt_field_addresses


###################################################################################################
#    MAIN LOGIC - MDT RELATED                                                                     #
###################################################################################################
def traverse_mdt_top_level(
    vmt_mdt_relations: dict[Address, Address],
    settings: ArchitectureSpecificSettings,
) -> dict:
    """
    Traverse the top-level structure of MDTs corresponding to a list of VMTs.

    Reads the number of method entry references from each MDT and resolves the addresses of the
    corresponding method entries. The result includes a mapping from VMTs to their MDT and a list of
    associated method entry addresses.

    Parameters:
        vmtMdtRelations (dict): Mapping of VMT addresses to their MDT addresses.
        settings (dict): Architecture-specific settings including pointer size.

    Returns:
        dict: A dictionary mapping each VMT address to a nested dictionary with its MDT address and
            a list of resolved method entry addresses.
    """
    # regrab memory interface
    memory = currentProgram.getMemory()

    vmt_mdt_top_level_info = {}

    for vmt_addr, mdt_addr in vmt_mdt_relations.items():
        check_cancel()
        # store address information for this MDT traversal
        vmt_mdt_top_level_info[vmt_addr] = {"mdt": mdt_addr, "methodEntries": []}

        # navigate to the NumOfMethodEntryRefs field
        num_of_method_entry_ref_structs_field = mdt_addr.add(2)
        # grab its 2B long content (architecture-independant)
        num_of_method_entry_ref_structs = memory.getShort(num_of_method_entry_ref_structs_field)
        debug(
            f"num_of_method_entry_ref_structs: {num_of_method_entry_ref_structs} for MDT @ "
            f"{mdt_addr}"
        )

        if num_of_method_entry_ref_structs == 0:
            continue

        # go to start of MethodEntryRef concatenation
        method_entry_refs_start_addr = num_of_method_entry_ref_structs_field.add(2)

        # get all starting addresses of the MDT's MethodEntries (`AddressOfMethodEntry`) and add
        # them to a list
        method_entry_addresses = []
        for i in range(num_of_method_entry_ref_structs):
            check_cancel()
            current_method_entry_ref_field = method_entry_refs_start_addr.add(
                i * (settings.ptr_size + 4)
            )
            try:
                current_method_entry_addr = read_ptr(
                    current_method_entry_ref_field, settings.ptr_size
                )
            except MemoryAccessException:
                warning(f"Could not read bytes @ {current_method_entry_ref_field}. Skipping.")
                continue

            method_entry_addresses.append(current_method_entry_addr)

        # add address information of found methodEntries to correlated MDT / VMT information
        vmt_mdt_top_level_info[vmt_addr]["methodEntries"].extend(method_entry_addresses)

    debug(f"Dictionary information after traverseMdtTopLevel(): {vmt_mdt_top_level_info}")
    return vmt_mdt_top_level_info


def traverse_param_entries(
    first_param_entry_addr: Address,
    num_of_param_entries: int,
    settings: ArchitectureSpecificSettings,
):
    """
    Traverse a sequence of ParamEntries and extract relevant RTTI and naming information.

    For each ParamEntry, this function reads and dereferences the RTTI address, resolves its
    namespace (if available), reads the associated Pascal-style parameter name, and collects
    the information in a structured dictionary.

    Parameters:
        firstParamEntryAddr (ghidra.program.model.address.Address): Starting address of the first
            ParamEntry.
        numOfParamEntries (int): Number of ParamEntries to process.
        settings (dict): Architecture-specific settings including pointer size.

    Returns:
        dict: Mapping from each ParamEntry's address to a dictionary containing the parameter's RTTI
            address, name, and namespace.
    """
    param_entries_info = {}
    current_addr = first_param_entry_addr
    for _ in range(num_of_param_entries):
        check_cancel()
        # cache addr at which each ParamEntry starts (as a key for storing information below)
        param_entry_addr = current_addr
        # get addr of RTTI object (indirect reference hence dereference)
        try:
            rtti = read_ptr(read_ptr(current_addr, settings.ptr_size), settings.ptr_size)
            rtti_namespace = traverse_rtti_object(rtti, settings)
        except Exception:
            rtti = None
            rtti_namespace = None

        # go to NameOfRtti field
        current_addr = current_addr.add(settings.ptr_size + 2)
        # grab name and size information
        param_name, str_len = read_pascal_str(current_addr)
        # go to AddrOfRtti field of next ParamEntry (remark: 3 bytes of additional data for
        # numOfParamEntries > 1)
        current_addr = current_addr.add(str_len + 3)
        param_entries_info[param_entry_addr] = {
            "AddrOfRtti": rtti,
            "ParamName": param_name,
            "rttiNamespace": rtti_namespace,
        }

    return param_entries_info


def traverse_method_entries(
    vmt_mdt_top_info: dict,
    settings: ArchitectureSpecificSettings,
) -> dict:
    """
    Traverse all MethodEntries associated with each VMT's MDT and collect detailed metadata.

    For each MethodEntry, this function extracts the function entry point, its name, return type
    RTTI information, and associated parameter entries. If any critical part cannot be dereferenced
    or lies outside of the executable section, the corresponding VMT is discarded from the final
    result.
    """
    # regrab memory interface
    memory = currentProgram.getMemory()

    # the zero-address for reusability
    all_zero_addr = convert_to_addr("0x0")

    # iterate over all MethodEntries of each VMT's MDT; by creating a new list, we can change the
    # size of the underlying dictionary during runtime
    for vmt in list(vmt_mdt_top_info.keys()):
        # store information about relevant fields for each MethodEntry of an MDT
        method_entries_info = {}

        for method_entry in vmt_mdt_top_info[vmt]["methodEntries"]:
            check_cancel()
            # dictionary to hold relevant information for a single MethodEntry
            method_entry_info = {}

            # grab entry point of the MethodEntry's function definition
            try:
                function_def_addr_field = method_entry.add(2)
            except AddressOutOfBoundsException:
                # this error can happen when a huge concatenation of addresses structure is falsely
                # detected as a VMT, hence, ignore its method entries
                break
            try:
                method_entry_info["functionEntryPoint"] = read_ptr(
                    function_def_addr_field, settings.ptr_size
                )
            except MemoryAccessException:
                warning(
                    f"Could not read bytes @ {function_def_addr_field}. Skipping methodEntry: "
                    f"{method_entry}."
                )
                continue

            # grab the corresponding function name
            name_of_function_addr = function_def_addr_field.add(settings.ptr_size)
            try:
                method_entry_info["nameOfFunction"], strLen = read_pascal_str(name_of_function_addr)
            except MemoryAccessException:
                warning(
                    f"Couldn't grab nameOfFunctionAddr: {name_of_function_addr}. Skipping "
                    f"methodEntry: {method_entry}."
                )
                continue

            # grab information about return type's RTTI class
            ret_type_addr_field = name_of_function_addr.add(strLen + 2)
            try:
                dereferenced_ret_type_addr = read_ptr(ret_type_addr_field, settings.ptr_size)
                # if all zero'd, void is the return type
                if dereferenced_ret_type_addr == all_zero_addr:
                    method_entry_info["returnTypeRttiAt"] = "n.a."
                    method_entry_info["returnTypeStr"] = "void"
                    detail(f"void return type applied for returnTypeAddress: {ret_type_addr_field}")
                else:
                    method_entry_info["returnTypeRttiAt"] = dereferenced_ret_type_addr
                    doubly_dereferenced_ret_type_addr = read_ptr(
                        dereferenced_ret_type_addr, settings.ptr_size
                    )
                    method_entry_info["returnTypeStr"] = traverse_rtti_object(
                        doubly_dereferenced_ret_type_addr, settings
                    )
            except MemoryAccessException:
                warning(f"Could not read bytes @ {ret_type_addr_field}. Skipping.")
                continue

            # get NumOfParamEntries
            num_of_param_entries_field = ret_type_addr_field.add(settings.ptr_size + 2)
            num_of_param_entries = memory.getByte(num_of_param_entries_field) & 0xFF

            # go to first ParamEntry substructure
            first_param_entry_field = num_of_param_entries_field.add(2)

            # sanity check for the ParamEntries: check if potential ParamEntries are within .text
            # section
            if not (
                settings.text_block_start_addr
                <= first_param_entry_field
                <= settings.text_block_end_addr
            ):
                # addresses outside the .text section mean false positive ParamEntries, hence remove
                # them
                del vmt_mdt_top_info[vmt]
                break

            # get information about position and names of the specific MethodEntry's parameters
            method_entry_info["paramEntries"] = traverse_param_entries(
                first_param_entry_field, num_of_param_entries, settings
            )

            # store information to the dictionary holding data for all MethodEntries of an MDT
            method_entries_info[method_entry] = method_entry_info

        # the else clause only triggers, if the inner loops break didn't trigger
        else:
            # store information to the dictionary holding all data
            vmt_mdt_top_info[vmt]["methodEntriesInfo"] = method_entries_info

    debug(f"Dictionary information after traverseMethodEntries(): {vmt_mdt_top_info}")
    return vmt_mdt_top_info


###################################################################################################
#    MAIN LOGIC - RTTI_CLASS RELATED                                                              #
###################################################################################################
def traverse_rtti_object(addr: Address, settings: dict) -> str | None:
    """
    Traverse a Delphi RTTI object and extract string information based on its magic byte.
    If the RTTI object is an RTTI_Class (0x07), its object name and namespace get returned, i.e.
    `Namespace.ClassName`.
    If the RTTI object is of any other RTTI object type, only the object's name gets returned, as
    the structure of the different RTTI object types have not yet been fully understood.

    Parameters:
        addr (ghidra.program.model.address.Address): The address pointing to the beginning of a
            potential RTTI object.
        settings (dict): Architecture-specific settings including pointer size.

    Returns:
        str | None: Namespace of the RTTI_Class's VMT as a string, or the the RTTI object's name
            (if it's not an RTTI_Class), or None if the structure is invalid.
    """
    # regrab memory interface
    memory = currentProgram.getMemory()
    magic_byte = memory.getByte(addr) & 0xFF

    if magic_byte > 0x15:
        warning(
            f"Tried to traverse data @ {addr}, but it's not an RTTI object! Skipping traversal."
        )
        return None

    # go to RttiObjectName field
    rtti_object_name_field = addr.add(1)
    # read Pascal String to get name of the RTTI object
    rtti_object_name, str_len = read_pascal_str(rtti_object_name_field)

    # if the traversed object is not of type RTTI_Class, only return its name as information
    if magic_byte != 0x07:
        return rtti_object_name

    # go to RttiNamespace field
    rtti_namespace_field = rtti_object_name_field.add(str_len + settings.ptr_size * 2 + 2)
    # read Pascal String to get the namespace of the RTTI_Class
    rtti_namespace, _ = read_pascal_str(rtti_namespace_field)

    # construct namespace from the PoV of a function in Delphi style (not yet C++!)
    namespace = rtti_namespace + "." + rtti_object_name

    return namespace


def add_namespace_information(vmt_rtti_relations: dict, symbol_info: dict, settings: dict) -> dict:
    """
    Augment symbol information with the namespace string derived via RTTI traversal. It ensures
    consistency with any VMTs previously filtered out.

    Parameters:
        vmtRttiRelations (dict): Mapping of VMT addresses to RTTI addresses.
        symbolInfo (dict): Dictionary holding previously gathered metadata.
        settings (dict): Architecture-specific configuration settings.

    Returns:
        dict: Updated symbolInfo dictionary with added `namespace` fields.
    """
    for vmt, rtti in vmt_rtti_relations.items():
        check_cancel()
        # if during traverseMethodEntries() a vmt had been removed, take this change into effect
        # here as well
        if vmt not in symbol_info:
            continue

        namespace = traverse_rtti_object(rtti, settings)
        debug(f"Mapping namespace information {namespace} to vmt @ {vmt}")
        symbol_info[vmt]["namespace"] = namespace

    debug(f"Final dictionary information: {symbol_info}")
    return symbol_info


###################################################################################################
#    MAIN LOGIC - TRANSFORMATION FUNCTIONS                                                        #
###################################################################################################
def prepare_namespace(namespace_str: str) -> Namespace:
    """
    Create or retrieve a nested namespace hierarchy in Ghidra's symbol table from a namespace
    string.

    Given a VMT address and a dot-separated namespace string, this function iteratively creates or
    retrieves each namespace component as a child of the previous one, starting from the global
    namespace. The "youngest" namespace object is returned.

    Parameters:
        namespaceStr (str): Dot-separated namespace string (e.g.,
            "MyNamespace.SubNamespace.ClassName").

    Returns:
        ghidra.program.model.symbol.Namespace: The final Namespace object corresponding to the
            deepest namespace level.
    """
    # grab ghidra's symbol table
    symbol_table = currentProgram.getSymbolTable()
    # split the namespace string at the first '.' character, returning a list of its parts
    namespace_parts = namespace_str.split(".")

    # start from the root namespace and iteratively grab or create its children
    parent_namespace = currentProgram.getGlobalNamespace()
    for part in namespace_parts:
        check_cancel()
        # look for an existing namespace with this name under the current parent or create it if
        # needed
        # remark: USER_DEFINED makes sure that later on, the information will not be overwritten by
        # ghidra
        try:
            parent_namespace = symbol_table.getOrCreateNameSpace(
                parent_namespace, part, SourceType.USER_DEFINED
            )
        except InvalidInputException:
            return None

    # return the final namespace object (e.g., TApplication)
    return parent_namespace


def prepare_data_type(type_string: str) -> DataType:
    """
    Returns the datatype concerning a string argument - either by mapping to a ghidra built-in
    datatype or by building the namespace of the RTTI type.

    Parameters:
        typeString (str): A string representing the datatype which shall be returned accordingly.

    Returns:
        DataType: The datatype object, either built by a constructor or a ghidra built-in datatype.
    """
    data_types = currentProgram.getDataTypeManager()

    # the following three lines are currently used for debugging purposes only
    global data_type_mapping
    if "." not in type_string:
        types.add(type_string)

    if type_string in data_type_mapping:
        # return mapped ghidra built-in datatype if it's a simple datatype
        final_data_type = data_type_mapping[type_string]()
    else:
        # define the class name and namespace
        param_namespace = prepare_namespace(type_string)
        param_class_name = type_string.split(".")[-1].rstrip(">")

        # create a class in the given namespace via the light-weight FlatProgramAPI function
        try:
            createClass(param_namespace, param_class_name)
        except DuplicateNameException:
            pass

        # create a categorypath and the actual datatype
        category_path = CategoryPath(
            "/" + param_namespace.getParentNamespace().getName(True).replace("::", "/")
        )  # → /Vcl/Forms
        data_type = StructureDataType(category_path, param_class_name, 0)

        # register the datatype with the DataTypeManager
        registered_data_type = data_types.addDataType(data_type, None)

        # create a pointer to the class (Delphi typically passes/returns class instances as
        # pointers) and return it
        final_data_type = PointerDataType(registered_data_type)

    return final_data_type


def apply_symbols(all_symbol_info: dict) -> dict:
    """
    Handles the actual symbol name recovering, given all previously gathered information.

    For every found VMT, the function iterates over the MethodEntry data and attempts to apply data
    like its name, parameter and return types and parameter names.

    Parameters:
        allSymbolInfo (dict): Dictionary holding previously gathered metadata.

    Returns:
        dict: Counts the numbers of VMTs, function names, and FQNs which have been fully recovered.
    """
    # grab necessary interfaces
    function_manager = currentProgram.getFunctionManager()

    # count how many VMT/functions have been fully recovered (evaluation information only)
    apply_count = {"vmt": 0, "function": 0, "fqn": 0, "return": 0, "paramSet": 0}

    for vmt, top_level_val in all_symbol_info.items():
        detail(f"[7/8] Currently proceessing symbol information for VMT @ {vmt} ...")
        apply_count["vmt"] += 1

        # get namespace information from ghidra's symbol table or create it if required
        if "namespace" not in top_level_val.keys():
            continue
        namespace_str = top_level_val["namespace"]
        if namespace_str is None:
            continue
        namespace = prepare_namespace(namespace_str)

        for second_level_val in top_level_val["methodEntriesInfo"].values():
            check_cancel()
            # grab all pieces of information from all MDT levels and recover symbols accordingly
            function_entry_point = second_level_val["functionEntryPoint"]
            function_name = second_level_val["nameOfFunction"]
            ret_type_str = second_level_val["returnTypeStr"]
            param_tuples = []
            for _, third_level_value in second_level_val["paramEntries"].items():
                if (
                    third_level_value["rttiNamespace"] is None
                    or third_level_value["ParamName"] == "Self"
                ):
                    param_tuples.append((third_level_value["ParamName"], namespace_str))
                    continue
                param_tuples.append(
                    (third_level_value["ParamName"], third_level_value["rttiNamespace"])
                )

            # -------------------------- APPLY FUNCTION NAMES ----------------------------------- #
            # start the actual symbol name recovery transformation with grabbing the function to
            # edit
            function = function_manager.getFunctionAt(function_entry_point)
            # if ghidra doesn't recognize this address already as a function
            if not function:
                # creating via the light-weight FlatProgramAPI function sets a name automatically
                function = createFunction(function_entry_point, function_name)
                # function could not be created for some reason, hence skip its symbol recovery
                if function is None:
                    continue
            else:
                # if function is already been known to ghidra, replace its name
                function.setName(function_name, SourceType.USER_DEFINED)

            apply_count["function"] += 1
            # ----------------------------------------------------------------------------------- #

            # -------------------------- APPLY NAMESPACES --------------------------------------- #
            if namespace is not None:
                try:
                    function.setParentNamespace(namespace)
                    detail(
                        f"Successfully applied FQN {namespace}::{function_name} function @ "
                        f"{function_entry_point}."
                    )
                    apply_count["fqn"] += 1
                except (
                    Exception
                ) as e:  # java.lang.IllegalArgumentException: namespace is from different program
                    # instance: System::TMarshal
                    warning(e)
                    warning(namespace)
                    pass
            # ----------------------------------------------------------------------------------- #

            # -------------------------- APPLY RETURN TYPES ------------------------------------- #
            if ret_type_str is not None:
                # retrieve DataType object for return type application
                final_data_type = prepare_data_type(ret_type_str)

                # replace return type
                function.setReturnType(final_data_type, SourceType.USER_DEFINED)

                detail(
                    f"Successfully applied return type {ret_type_str} to function "
                    f"@ {function_entry_point}."
                )
                apply_count["return"] += 1
            # ----------------------------------------------------------------------------------- #

            # -------------------------- APPLY PARAM TUPLES ------------------------------------- #
            params = []
            for param_name, rtti_name in param_tuples:
                # retrieve DataType object for parameter application preparation
                final_data_type = prepare_data_type(rtti_name)

                # Create parameters using ParameterImpl(name, dataType, program) and add them to
                param = ParameterImpl(param_name, final_data_type, currentProgram)
                params.append(param)

            # replace parameters
            try:
                function.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    params,
                )
            # skip in case of invalid symbol names
            except InvalidInputException:
                continue

            apply_count["paramSet"] += 1
            # ----------------------------------------------------------------------------------- #

    return apply_count


###################################################################################################
#    MAIN LOGIC - ACTUAL MAIN                                                                     #
###################################################################################################
def main() -> None:
    """
    Main function orchestrating the analysis and recovery of symbol and RTTI information from an
    executable's VMTs and MDTs within Ghidra.
    """
    # retrieve original function count at program start
    original_function_count = currentProgram.getFunctionManager().getFunctionCount()

    # grab relevant numbers which depend on the architecture of the executable
    settings = get_architecture_settings()

    # get memory interface of executable (beware: "memory changes should generally be completed
    # prior to analysis.")
    memory = currentProgram.getMemory()
    text_section = get_text_section(memory)
    settings.text_block_start_addr = text_section.getStart()
    settings.text_block_end_addr = text_section.getEnd()

    # print more general information
    print(f"|> Size of .text section: {text_section.getSizeAsBigInteger()}")

    info("[1/8] Starting to scan for candidate VMTs & performing sanity checks...")
    vmt_addresses = find_vmts(settings)

    info("[2/8] Grabbing the MDT of every found VMT...")
    vmt_mdt_relations = get_vmt_field_addresses(vmt_addresses, settings, settings.mdt_offset, "MDT")

    info("[3/8] Grabbing the RTTI_Class of every found VMT...")
    vmt_rtti_relations = get_vmt_field_addresses(
        vmt_addresses, settings, settings.rtti_offset, "VmtRtti"
    )

    # find all starting addresses of all MethodEntry substructures of every MDT
    # the result is structured as follows:
    # {<vmtAddr>: {"mdt": <mdtAddress>, "methodEntries":[<methodEntry1Addr>, <methodEntry2Addr>,
    # ...]}}
    info("[4/8] Grabbing the MethodEntries of every found MDT...")
    vmt_mdt_top_level_info = traverse_mdt_top_level(vmt_mdt_relations, settings)

    # entlang der MDT Struktur entlang hangeln, um relevante Daten zu erhalten.
    info("[5/8] Extracting information of all MethodEntries of every found MDT...")
    vmt_mdt_symbol_info = traverse_method_entries(vmt_mdt_top_level_info, settings)

    # complete symbol recovery information by calling traverseRttiClass(addr, settings) for all VMTs
    info("[6/8] Extracting the RTTI namespaces for every VMT/MDT...")
    all_symbol_info = add_namespace_information(vmt_rtti_relations, vmt_mdt_symbol_info, settings)

    # apply symbol name recovery
    info("[7/8] Reconstructing all symbol names...")
    recovery_counts = apply_symbols(all_symbol_info)

    # print final statistics
    total_function_count = currentProgram.getFunctionManager().getFunctionCount()
    info(f"[8/8] Statistics: Pre-execution number of functions: {original_function_count}")
    info(f"[8/8] Statistics: Post-execution number of functions: {total_function_count}")
    info(f"[8/8] Statistics: Number of VMTs found: {len(vmt_addresses)}")
    info(
        f"[8/8] Statistics: Number of symbol recovered VMTs: {recovery_counts['vmt']}, yielding "
        f"{recovery_counts['vmt']/len(vmt_addresses)*100:.2f}% of all found VMTs."
    )
    info(
        f"[8/8] Statistics: Number of symbol recovered functions: {recovery_counts['function']}, "
        f"yielding {recovery_counts['function']/total_function_count*100:.2f}% of all functions; "
        f"or {recovery_counts['function']/original_function_count*100:.2f}% when using "
        "pre-execution function count."
    )
    info(
        f"[8/8] Statistics: Number of applied FQNs: {recovery_counts['fqn']}, yielding "
        f"{recovery_counts['fqn']/total_function_count*100:.2f}% of all functions; or "
        f"{recovery_counts['fqn']/original_function_count*100:.2f}% when using pre-execution "
        "function count."
    )
    info(
        f"[8/8] Statistics: Number of applied return types: {recovery_counts['return']}, yielding "
        f"{recovery_counts['return']/total_function_count*100:.2f}% of all functions; or "
        f"{recovery_counts['return']/original_function_count*100:.2f}% when using pre-execution "
        "function count."
    )
    info(
        f"[8/8] Statistics: Number of applied parameter sets: {recovery_counts['paramSet']}, "
        f"yielding {recovery_counts['paramSet']/total_function_count*100:.2f}% of all functions; "
        f"or {recovery_counts['paramSet']/original_function_count*100:.2f}% when using "
        "pre-execution function count."
    )
    info("[8/8] Finished.")

    # the following two lines are for debugging purposes only
    global types
    debug(types)


if pyghidra.started():
    try:
        main()
    except MonitorCancel:
        pass
