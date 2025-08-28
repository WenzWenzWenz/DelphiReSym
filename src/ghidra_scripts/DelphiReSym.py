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
from dataclasses import dataclass, field
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
        if isinstance(x, Address):
            return x
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
    """
    This enables Ghidra-GUI's "Cancel" button to actually stop the execution. 
    """
    if monitor.isCancelled():
        raise MonitorCancel


###################################################################################################
#    CONFIGS'n'CONSTANTS                                                                          #
###################################################################################################
# set whether or not to print detailed debug information to stdout
VERBOSE_DEBUG = False
# set whether or not to print less detailed debug information to stdout
VERBOSE_INFO = True
# set whether or not to print warning information to stdout
VERBOSE_WARNING = False

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
    Read a specified address of the given size from memory.

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

    The string format expects the first byte to contain the length, followed by the corresponding
    characters whose number is equal to that length.

    Parameters:
        addr (ghidra.program.model.address.Address): The memory address where the Pascal-String
            starts.

    Returns:
        tuple[str,int]: The decoded string and its total byte length (including length byte).
    """
    pascal_str = ""
    
    memory_interface = currentProgram.getMemory()
    pascal_str_len = memory_interface.getByte(addr) & 0xFF

    first_char_addr = addr.add(1)
    for i in range(pascal_str_len):
        pascal_str += chr(memory_interface.getByte(first_char_addr.add(i)) & 0xFF)

    return pascal_str, pascal_str_len + 1


@dataclass
class ArchitectureSpecificSettings:
    ptr_size: int
    jump_dist: int
    text_block_start_addr: Address
    text_block_end_addr: Address

    @property
    def mdt_offset(self) -> int:
        return self.ptr_size * 6

    @property
    def rtti_offset(self) -> int:
        return self.ptr_size * 4


def get_architecture_settings(text_section: MemoryBlock) -> ArchitectureSpecificSettings:
    """
    Return a dataclass instance holding information about architecture-specific settings, including
    pointer size and architecture specific jump distances to MDT and RTTI_Class.

    The text block start and end addresses are just place holders at initialization time.

    Parameters:
        text_section (ghidra.program.model.mem.MemoryBlock): The .text section memory block to
            look up its boarders for.

    Returns:
        ArchitectureSpecificSettings: A dataclass instance holding architecture settings.
    """
    start = text_section.getStart()
    end = text_section.getEnd()

    ptr_size = currentProgram.getDefaultPointerSize()
    if ptr_size == 4:
        return ArchitectureSpecificSettings(
            ptr_size=4, jump_dist=88, text_block_start_addr=start, text_block_end_addr=end
        )
    if ptr_size == 8:
        return ArchitectureSpecificSettings(
            ptr_size=8, jump_dist=200, text_block_start_addr=start, text_block_end_addr=end
        )
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
    candidate_addr: Address,
    next_struct: Address,
    settings: ArchitectureSpecificSettings,
) -> bool:
    """
    Perform several sanity checks on the candidate VMT.

    Five fields of the VMT have been chosen for the sanity checks; three of which must always be
    filled with valid addresses in the range of the .text section. Same holds true for the other two
    fields, which alternatively can be NULL too. As yet another sanity check, the address of the
    MDT must be larger than the address of its VMT.

    Parameters:
        candidate_addr (ghidra.program.model.address.Address): The candidate VMT's address to be
            sanity-checked.
        next_struct (ghidra.program.model.address.Address): The value of the VMT's NextStruct field,
            used for a sanity check.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        bool: Result of candidate VMT sanity checks.
    """
    ptr_size = settings.ptr_size
    
    addresses = []
    addresses.append(next_struct)

    mdt_addr = candidate_addr.add(ptr_size * 6)
    mdt = read_ptr(mdt_addr, ptr_size)
    if mdt:
        addresses.append(mdt)
        # MDTs are located at higher addresses than their corresponding VMTs
        if mdt <= candidate_addr:
            return False

    # sanity check for all 10 mandatory functions at the end of the VMT in a loop
    for current_field_number in range(11, 22):
        # exclude the SafeCallExceptionMethod field since it is the only optional one of the 10
        if current_field_number != 14:
            current_field = candidate_addr.add(ptr_size * current_field_number)
            addresses.append(read_ptr(current_field, ptr_size))

    # returns True if all grabbed addresses are within range of the .text section
    return all(
        settings.text_block_start_addr
        <= addr
        < settings.text_block_end_addr.subtract(settings.ptr_size)
        for addr in addresses
    )


def find_vmts(settings: ArchitectureSpecificSettings) -> list[Address]:
    """
    Scan the .text section for potential VMT addresses.

    Uses a sliding window approach to identify forward references of a specific size that may
    indicate the presence of a VMT. Applies sanity checks before accepting each candidate.

    Parameters:
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        list[Address]: A list of addresses of candidate VMTs.
    """
    vmt_addresses = []

    text_block_size = settings.text_block_end_addr.subtract(settings.text_block_start_addr)

    current_address = settings.text_block_start_addr
    while current_address < settings.text_block_end_addr.subtract(settings.ptr_size - 1):
        check_cancel()
        
        current_val = read_ptr(current_address, settings.ptr_size)
        distance = current_val.subtract(current_address)
        
        if distance == settings.jump_dist:
            if not check_vmt_candidate(current_address, current_val, settings):
                debug(f"REJECTED VMT candidate @ {current_address}. Didn't pass sanity checks.")
                current_address = current_address.add(1)
                continue

            vmt_addresses.append(current_address)
            debug(f"VMT @ {current_address} passed sanity checks. Adding it to the list of VMTs.")

        current_address = current_address.add(1)

        # progress bar, since this part of the code takes the longest amount of time
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
) -> dict:
    """
    Resolve the addresses of specific VMT fields and validate their targets.

    For each VMT address, this function computes the address of the requested field (e.g., MDT or
    RTTI), dereferences it, and adds it to a returned dict.

    Parameters:
        vmt_addresses (list[Address]): List of candidate VMT addresses.
        settings (dict): A dataclass instance holding architecture settings.
        fieldname (str): Key indicating which field to extract (e.g., 'mdtOffset', 'rttiOffset').

    Returns:
        dict[Address, Address]: Mapping from VMT address to the resolved field address.
    """
    vmt_field_addresses = {}

    for vmt_addr in vmt_addresses:
        check_cancel()

        field_addr = vmt_addr.add(offset)
        try:
            field_val = read_ptr(field_addr, settings.ptr_size)
        except MemoryAccessException:
            warning(f"Could not read bytes @ {field_addr}. Skipping.")
            continue
        vmt_field_addresses[vmt_addr] = field_val

    return vmt_field_addresses


###################################################################################################
#    DATA CLASSES for VirtualMethodTables, MethodDefinitionTables, MethodEntries and Parameters   #
###################################################################################################
@dataclass
class ParamInfo:
    rtti_addr: Address
    param_name: str
    rtti_namespace: str


@dataclass
class MeInfo:
    func_entry_point: Optional[Address] = 0
    func_name: Optional[str] = ""
    ret_type_at: Optional[Address | str] = "n.a."
    ret_type_str: Optional[str] = "void"
    param_entries: dict[Address, ParamInfo] = field(default_factory=dict)


@dataclass
class MdtMeInfo:
    mdt: Address
    namespace: Optional[str] = ""
    method_entries: dict[Address, MeInfo] = field(default_factory=dict)


@dataclass
class VmtMdtMapping:
    entries: dict[Address, MdtMeInfo] = field(default_factory=dict)


###################################################################################################
#    MAIN LOGIC - MDT RELATED                                                                     #
###################################################################################################
def get_method_entries(
    start_addr: Address,
    num_of_method_entry_refs: int,
    settings: ArchitectureSpecificSettings,
    info: MdtMeInfo,
 ) -> MdtMeInfo:
    """
    Given an instance of an MdtMeInfo dataclass, grab each method entry address and prepare MeInfo
    dataclass instances for each of them.

    Parameters:
        start_addr (Address): Address of the first method entry in an MDT.
        num_of_method_entry_ref_structs (dict): Number of method entries for an MDT.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.
        current_info (MdtMeInfo): A dataclass instance which allows storage of method entry
            information corresponding to MDTs.

    Returns:
        MdtMeInfo: The transformed dataclass instance, in which for each method entry an MeInfo
            dataclass instance is prepared to be filled with information later.
    """
    for i in range(num_of_method_entry_refs):
        check_cancel()

        current_method_entry_ref_field = start_addr.add(
            i * (settings.ptr_size + 4)
        )
        try:
            current_method_entry_addr = read_ptr(
                current_method_entry_ref_field, settings.ptr_size
            )
        except MemoryAccessException:
            warning(f"Could not read bytes @ {current_method_entry_ref_field}. Skipping.")
            continue

        info.method_entries[current_method_entry_addr] = MeInfo()

    return info


def traverse_mdt_top_level(
    vmt_mdt_relations: dict[Address, Address],
    settings: ArchitectureSpecificSettings,
) -> VmtMdtMapping:
    """
    Traverse the top-level structure of MDTs corresponding to a list of VMTs.

    Reads the number of method entry references from each MDT and resolves the addresses of the
    corresponding method entries. The result includes a mapping from VMTs to their MDT and a list of
    associated method entry addresses.

    Parameters:
        vmt_mdt_relations (dict): Mapping of VMT addresses to their MDT addresses.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        VmtMdtMapping: A dataclass instance mapping each VMT address to its MDT address and a list
        of resolved method entry addresses (yet without symbolic information).
    """
    mapping = VmtMdtMapping()

    memory_interface = currentProgram.getMemory()
    
    for vmt_addr, mdt_addr in vmt_mdt_relations.items():
        check_cancel()

        num_of_method_entry_refs_field = mdt_addr.add(2)
        num_of_method_entry_refs = memory_interface.getShort(num_of_method_entry_refs_field)
        if num_of_method_entry_refs == 0:
            continue

        # store address information for this MDT traversal
        current_info = MdtMeInfo(mdt=mdt_addr)

        method_entry_refs_start_addr = num_of_method_entry_refs_field.add(2)

        # extend current_info with method entry address information
        current_info = get_method_entries(
            method_entry_refs_start_addr, num_of_method_entry_refs, settings, current_info
        )
        mapping.entries[vmt_addr] = current_info

    return mapping


def traverse_param_entries(
    first_param_entry_addr: Address,
    num_of_param_entries: int,
    settings: ArchitectureSpecificSettings,
) -> dict[Address, ParamInfo]:
    """
    Traverse a sequence of ParamEntries and extract relevant RTTI and naming information.

    For each ParamEntry, this function reads and dereferences the RTTI address, resolves its
    namespace (if available), reads the associated Pascal-style parameter name, and collects
    the information in a structured dictionary.

    Parameters:
        first_param_entry_addr (ghidra.program.model.address.Address): Starting address of the first
            ParamEntry.
        num_of_param_entries (int): Number of ParamEntries to process.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        dict[ghidra.program.model.address.Address,ParamInfo]: Mapping from each ParamEntry's address
            to a dictionary containing the parameter's RTTI address, name, and namespace.
    """
    param_entries_info = {}

    current_addr = first_param_entry_addr

    for _ in range(num_of_param_entries):
        check_cancel()

        # grab information
        param_entry_addr = current_addr
        try:
            rtti = read_ptr(read_ptr(current_addr, settings.ptr_size), settings.ptr_size)
            rtti_namespace = traverse_rtti_object(rtti, settings)
        except Exception:
            rtti = None
            rtti_namespace = None
        param_name_addr = current_addr.add(settings.ptr_size + 2)
        param_name, str_len = read_pascal_str(param_name_addr)

        # store information
        param_entries_info[param_entry_addr] = ParamInfo(
            rtti_addr=rtti, param_name=param_name, rtti_namespace=rtti_namespace
        )

        # next ParamEntry
        current_addr = param_name_addr.add(str_len + 3)

    return param_entries_info


def extract_func_entry_point(
    method_entry_addr: Address, settings: ArchitectureSpecificSettings
) -> Address:
    """
    Extract the address of a function entry point given a specific MethodEntry address.

    Parameters:
        method_entry_addr (ghidra.program.model.address.Address): Starting address of MethodEntry.
        settings (dict): Architecture-specific settings including pointer size.

    Returns:
        ghidra.program.model.address.Address: The address of the extracted function entry point.
    """
    function_def_addr_field = method_entry_addr.add(2)
    return read_ptr(function_def_addr_field, settings.ptr_size)


def extract_func_name(
    method_entry_addr: Address, settings: ArchitectureSpecificSettings
) -> tuple[str, int] | tuple[None, None]:
    """
    Extract the name of a function given a specific MethodEntry address.

    Parameters:
        method_entry_addr (ghidra.program.model.address.Address): Starting address of MethodEntry.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        tuple(str,int): The name of the function as a String and its length.
    """
    name_of_function_addr = method_entry_addr.add(settings.ptr_size + 2)
    try:
        func_name, str_len = read_pascal_str(name_of_function_addr)
        return func_name, str_len
    except MemoryAccessException:
        warning(f"Grab of nameOfFunctionAddr failed. Skipping ME: {method_entry_addr}.")
        return None, None


def extract_ret_type(
    method_entry_addr: Address, func_name_len: int, settings: ArchitectureSpecificSettings
) -> tuple[Address, str] | tuple[None, None]:
    """
    Extract the return type of a function given a specific MethodEntry address.

    Parameters:
        method_entry_addr (ghidra.program.model.address.Address): Starting address of MethodEntry.
        func_name_len (int): The length of the function name preceeding the return type information.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        tuple(ghidra.program.model.address.Address,str): The address of the RTTI return type and its
            String represenation (=return type name).
    """
    all_zero_addr = convert_to_addr("0x0")

    ret_type_addr_field = method_entry_addr.add(func_name_len + settings.ptr_size + 4)
    try:
        dereferenced_ret_type_addr = read_ptr(ret_type_addr_field, settings.ptr_size)
        ret_type_at = dereferenced_ret_type_addr
        
        if dereferenced_ret_type_addr == all_zero_addr:
            return ret_type_at, "void"
        
        doubly_dereferenced_ret_type_addr = read_ptr(
            dereferenced_ret_type_addr, settings.ptr_size
        )
        ret_type_str = traverse_rtti_object(
            doubly_dereferenced_ret_type_addr, settings
        )
    except MemoryAccessException:
        warning(
            warning(f"Read of return type failed. Skipping ME: {method_entry_addr}.")
        )
        return None, None

    return ret_type_at, ret_type_str


def extract_parameters(
    method_entry_addr: Address, func_name_len: int, settings: ArchitectureSpecificSettings
) -> dict[Address, ParamInfo] | None:
    """
    Extract the parameter information of a function given a specific MethodEntry address.

    Parameters:
        method_entry_addr (ghidra.program.model.address.Address): Starting address of MethodEntry.
        func_name_len (int): The length of the function name preceeding the return type information.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        dict[ghidra.program.model.address.Address,ParamInfo]: Mapping from each ParamEntry's address
            to a dictionary containing the parameter's RTTI address, name, and namespace.
    """
    memory_interface = currentProgram.getMemory()

    num_of_param_entries_field = method_entry_addr.add(func_name_len + 2 * settings.ptr_size + 6)
    num_of_param_entries = memory_interface.getByte(num_of_param_entries_field) & 0xFF

    first_param_entry_field = num_of_param_entries_field.add(2)
    # address outside the .text section => false positive
    if not (
        settings.text_block_start_addr
        <= first_param_entry_field
        <= settings.text_block_end_addr
    ):
        return None

    return traverse_param_entries(first_param_entry_field, num_of_param_entries, settings)


def traverse_method_entries(
    vmt_mdt_top_info: VmtMdtMapping,
    settings: ArchitectureSpecificSettings,
) -> VmtMdtMapping:
    """
    Traverse all MethodEntries associated with each VMT's MDT and collect detailed metadata.

    For each MethodEntry, this function extracts the function entry point, its name, return type
    RTTI information, and associated parameter entries. If any critical part cannot be dereferenced
    or lies outside of the executable section, the corresponding VMT is discarded from the final
    result.

    Parameters:
        vmt_mdt_top_info (VmtMdtMapping): A dataclass instance holding information about VMT-MDT-ME
            mapping.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        VmtMdtMapping: First argument with now filled-in symbolic information concerning MDTs.
    """
    # iterate over all MethodEntries of each VMT's MDT
    for vmt, mdt_me_info in list(vmt_mdt_top_info.entries.items()):

        method_entries_info = mdt_me_info

        for method_entry_addr in mdt_me_info.method_entries.keys():
            check_cancel()

            try:
                func_entry_point = extract_func_entry_point(method_entry_addr, settings)
            except MemoryAccessException:
                warning(f"Read of func entry point failed. Skipping ME: {method_entry_addr}.")
                continue
            # Delphi executables often contain a large concatenation of addresses at the very
            # end of the .text section -> falsely detected as a valid VMT
            except AddressOutOfBoundsException:
                break

            func_name, func_name_len = extract_func_name(method_entry_addr, settings)
            if not func_name:
                continue

            ret_type_addr, ret_type_str = extract_ret_type(method_entry_addr, func_name_len, settings)
            if not (ret_type_addr or ret_type_str):
                continue

            params = extract_parameters(method_entry_addr, func_name_len, settings)
            if not params:
                del vmt_mdt_top_info.entries[vmt]
                break

            # store gathered information
            method_entry_info = MeInfo(
                func_entry_point=func_entry_point,
                func_name=func_name,
                ret_type_at=ret_type_addr,
                ret_type_str=ret_type_str,
                param_entries=params,
            )
            method_entries_info.method_entries[method_entry_addr] = method_entry_info

        # store information only if the loop didn't break (= all MethodEntries of MDT are valid)
        else:
            vmt_mdt_top_info.entries[vmt] = method_entries_info

    debug(f"Symbolic information after traverse_method_entries(): {vmt_mdt_top_info}")
    return vmt_mdt_top_info


###################################################################################################
#    MAIN LOGIC - RTTI_CLASS RELATED                                                              #
###################################################################################################
def traverse_rtti_object(addr: Address, settings: ArchitectureSpecificSettings) -> str | None:
    """
    Traverse a Delphi RTTI object and extract string information based on its magic byte.

    If the RTTI object is an RTTI_Class (0x07), its object name and namespace get returned, i.e.
    `Namespace.ClassName`.
    If the RTTI object is of any other RTTI object type, only the object's name gets returned, as
    the structure of the different RTTI object types have not yet been fully understood.

    Parameters:
        addr (ghidra.program.model.address.Address): The address pointing to the beginning of a
            potential RTTI object.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        str|None: Namespace of the RTTI_Class's VMT as a string, or the the RTTI object's name
            (if it's not an RTTI_Class), or None if the structure is invalid.
    """
    memory_interface = currentProgram.getMemory()
    magic_byte = memory_interface.getByte(addr) & 0xFF

    if magic_byte > 0x15:
        warning(f"Tried to traverse data @{addr}, but it's not an RTTI object! Skipping.")
        return None

    rtti_object_name_field = addr.add(1)
    rtti_object_name, str_len = read_pascal_str(rtti_object_name_field)

    # not of type RTTI_Class
    if magic_byte != 0x07:
        return rtti_object_name

    rtti_namespace_field = rtti_object_name_field.add(str_len + 2 * settings.ptr_size + 2)
    rtti_namespace, _ = read_pascal_str(rtti_namespace_field)

    namespace = rtti_namespace + "." + rtti_object_name

    return namespace


def add_namespace_information(
    vmt_rtti_relations: dict, symbol_info: VmtMdtMapping, settings: dict
) -> VmtMdtMapping:
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
        if vmt not in symbol_info.entries:
            continue

        symbol_info.entries[vmt].namespace = traverse_rtti_object(rtti, settings)

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


def apply_symbols(all_symbol_info: VmtMdtMapping) -> dict[str, int]:
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

    for vmt, mdt_me_info in all_symbol_info.entries.items():
        debug(f"[7/8] Currently proceessing symbol information for VMT @ {vmt} ...")
        apply_count["vmt"] += 1

        # get namespace information from ghidra's symbol table or create it if required
        namespace_str = mdt_me_info.namespace
        if namespace_str is None or not namespace_str:
            continue
        namespace = prepare_namespace(namespace_str)

        for _, me_info in mdt_me_info.method_entries.items():
            check_cancel()
            # grab all pieces of information from all MDT levels and recover symbols accordingly
            func_entry_point = me_info.func_entry_point
            func_name = me_info.func_name
            ret_type_str = me_info.ret_type_str
            param_tuples = []
            for _, param_info in me_info.param_entries.items():
                # TODO: I think I can manage this now more easily with default value in dataclass
                # and not overwriting checks
                if param_info.rtti_namespace is None or param_info.param_name == "Self":
                    param_tuples.append((param_info.param_name, namespace_str))
                    continue
                param_tuples.append((param_info.param_name, param_info.rtti_namespace))

            # -------------------------- APPLY FUNCTION NAMES ----------------------------------- #
            # start the actual symbol name recovery transformation with grabbing the function to
            # edit
            function = function_manager.getFunctionAt(convert_to_addr(func_entry_point))
            # if ghidra doesn't recognize this address already as a function
            if not function:
                # creating via the light-weight FlatProgramAPI function sets a name automatically
                function = createFunction(convert_to_addr(func_entry_point), func_name)
                # function could not be created for some reason, hence skip its symbol recovery
                if function is None:
                    continue
            else:
                # if function is already been known to ghidra, replace its name
                function.setName(func_name, SourceType.USER_DEFINED)

            apply_count["function"] += 1
            # ----------------------------------------------------------------------------------- #

            # -------------------------- APPLY NAMESPACES --------------------------------------- #
            if namespace is not None:
                try:
                    function.setParentNamespace(namespace)
                    debug(
                        f"Successfully applied FQN {namespace}::{func_name} function @ "
                        f"{func_entry_point}."
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

                debug(
                    f"Successfully applied return type {ret_type_str} to function "
                    f"@ {func_entry_point}."
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
    original_function_count = currentProgram.getFunctionManager().getFunctionCount()

    memory_interface = currentProgram.getMemory()
    text_section = get_text_section(memory_interface)
    settings = get_architecture_settings(text_section)

    # print more general information
    print(f"|> Size of .text section: {text_section.getSizeAsBigInteger()}")

    info("[1/8] Starting to scan for candidate VMTs & performing sanity checks...")
    vmt_addresses = find_vmts(settings)

    info("[2/8] Grabbing the MDT of every found VMT...")
    vmt_mdt_relations = get_vmt_field_addresses(vmt_addresses, settings, settings.mdt_offset)

    info("[3/8] Grabbing the RTTI_Class of every found VMT...")
    vmt_rtti_relations = get_vmt_field_addresses(vmt_addresses, settings, settings.rtti_offset)

    # find all starting addresses of all MethodEntry substructures of every MDT
    # the result is structured as follows:
    # {<vmtAddr>: {"mdt": <mdtAddress>, "methodEntries":[<methodEntry1Addr>, <methodEntry2Addr>,
    # ...]}}
    info("[4/8] Grabbing the MethodEntries of every found MDT...")
    vmt_mdt_top_level = traverse_mdt_top_level(vmt_mdt_relations, settings)

    # entlang der MDT Struktur entlang hangeln, um relevante Daten zu erhalten.
    info("[5/8] Extracting information of all MethodEntries of every found MDT...")
    vmt_mdt_symbols = traverse_method_entries(vmt_mdt_top_level, settings)

    # complete symbol recovery information by calling traverseRttiClass(addr, settings) for all VMTs
    info("[6/8] Extracting the RTTI namespaces for every VMT/MDT...")
    all_symbols = add_namespace_information(vmt_rtti_relations, vmt_mdt_symbols, settings)

    # apply symbol name recovery
    info("[7/8] Reconstructing all symbol names...")
    recovery_counts = apply_symbols(all_symbols)

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
