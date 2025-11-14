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

from typing import TYPE_CHECKING, cast, Optional, Any, NamedTuple
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import createFunction, createClass, getFunctionAt              # type: ignore

from ghidra.program.model.symbol import SourceType, Namespace                   # type: ignore
from ghidra.program.model.listing import ParameterImpl, Function, Program       # type: ignore
from ghidra.program.model.mem import MemoryAccessException, Memory, MemoryBlock # type: ignore
from ghidra.program.model.address import Address, AddressOutOfBoundsException   # type: ignore
from ghidra.util.task import TaskMonitor                                        # type: ignore
from ghidra.util.exception import InvalidInputException, DuplicateNameException # type: ignore
from ghidra.program.model.data import (                                         # type: ignore
    DataTypeConflictHandler,
    DataType,
    PointerDataType,
    BooleanDataType,
    VoidDataType,
    DoubleDataType,
    IntegerDataType,
    ShortDataType,
    CharDataType,
    UnsignedIntegerDataType,
    ByteDataType,
    CategoryPath,
    StructureDataType,
    PascalUnicodeDataType,
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

# set whether or not to profile the script
ENABLE_PROFILING = False

# set whether or not to show entire namespaces of all types within templates (in symbol tree view)
SHOW_ENTIRE_TEMPLATE_NAMESPACES = True

# set whether or not to extract virtual methods and store them to additionally created
# "VT_<structname>" structures
VT_CREATION = True

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
    # not StringDataType since it is a factory datatype
    "string": lambda: PointerDataType(CharDataType()),
    # for reference: https://docwiki.embarcadero.com/RADStudio/Sydney/en/String_Types_(Delphi)
    "WideString": lambda: PointerDataType(PascalUnicodeDataType()),
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
    """
    memory = currentProgram.getMemory()
    return (
        convert_to_addr(memory.getInt(addr))
        if ptr_size == 4
        else convert_to_addr(memory.getLong(addr))
    )


def read_pascal_str(addr: Address) -> str:
    """
    Read a Pascal-String from memory at the specified address.

    The string format expects the first byte to contain the length, followed by the corresponding
    characters whose number is equal to that length.
    """
    pascal_str = ""

    memory_interface = currentProgram.getMemory()
    pascal_str_len = memory_interface.getByte(addr) & 0xFF

    first_char_addr = addr.add(1)
    for i in range(pascal_str_len):
        pascal_str += chr(memory_interface.getByte(first_char_addr.add(i)) & 0xFF)

    return pascal_str


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
    """
    start = text_section.getStart()  # place-holder at initialization time
    end = text_section.getEnd()  # place-holder at initialization time

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
    Returns a boolean result of several sanity checks on the candidate VMT.
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

    for current_field_number in range(11, 22):
        # exclude the SafeCallExceptionMethod field since it is the only optional one of the 10
        if current_field_number != 14:
            current_field = candidate_addr.add(ptr_size * current_field_number)
            addresses.append(read_ptr(current_field, ptr_size))

    return all(
        settings.text_block_start_addr
        <= addr
        < settings.text_block_end_addr.subtract(settings.ptr_size)
        for addr in addresses
    )


def find_vmts(settings: ArchitectureSpecificSettings) -> list[Address]:
    """
    Scan the .text section for potential VMT addresses, using a sliding window approach to identify
    forward references of a specific size (candidate VMTs). Applies sanity checks before accepting
    each candidate. Returns the sanity checked list of VMTs.
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
                    f"[1/8] Processed {round((progress / text_block_size) * 100)}% addresses in .text "
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
class ParameterInfo:
    rtti_addr: Address
    parameter_name: str
    rtti_namespace: str


@dataclass
class MeInfo:
    function_entry_point: Optional[Address] = 0
    function_name: Optional[str] = ""
    return_type_at: Optional[Address | str] = "n.a."
    return_type_str: Optional[str] = "void"
    parameter_entries: dict[Address, ParameterInfo] = field(default_factory=dict)


@dataclass
class MdtMeInfo:
    mdt: Address
    namespace: Optional[str] = ""
    method_entries: dict[Address, MeInfo] = field(default_factory=dict)


@dataclass
class VmtMdtMapping:
    entries: dict[Address, MdtMeInfo] = field(default_factory=dict)


###################################################################################################
#    MAIN LOGIC - RTTI_CLASS RELATED                                                              #
###################################################################################################
def traverse_rtti_object(addr: Address, settings: ArchitectureSpecificSettings) -> str | None:
    """
    Traverse a Delphi RTTI object and extract string information based on its magic byte.

    If the RTTI object is an RTTI_Class (magic byte 0x07), return its object name and namespace.
    If the RTTI object is of any other RTTI object type, only the object's name gets returned, as
    the structure of the different RTTI object types have not yet been fully understood.
    """
    memory_interface = currentProgram.getMemory()
    magic_byte = memory_interface.getByte(addr) & 0xFF

    if magic_byte > 0x15:
        warning(f"Tried to traverse data @{addr}, but it's not an RTTI object! Skipping.")
        return None

    rtti_object_name_field = addr.add(1)
    rtti_object_name = read_pascal_str(rtti_object_name_field)

    # not of type RTTI_Class  # TODO: Think about mapping WideStr etc. to `System.` instead of PaUni 
    if magic_byte != 0x07:
        return rtti_object_name

    rtti_namespace_field = rtti_object_name_field.add(
        len(rtti_object_name) + 1 + 2 * settings.ptr_size + 2
    )
    rtti_namespace = read_pascal_str(rtti_namespace_field)

    namespace = rtti_namespace + "." + rtti_object_name

    return namespace


def add_namespace_information(
    vmt_rtti_relations: dict, symbol_info: VmtMdtMapping, settings: ArchitectureSpecificSettings
) -> VmtMdtMapping:
    """
    Augment symbol information with the namespace string derived via RTTI traversal. The function
    ensures consistency with any VMTs previously filtered out.
    """
    for vmt, rtti in vmt_rtti_relations.items():
        check_cancel()

        # can happen if a VMT was removed during traverseMethodEntries()
        if vmt not in symbol_info.entries:
            continue

        symbol_info.entries[vmt].namespace = traverse_rtti_object(rtti, settings)

    debug(f"Final dictionary information after add_namespace_information(): {symbol_info}")
    return symbol_info


###################################################################################################
#    MAIN LOGIC - MDT RELATED                                                                     #
###################################################################################################
def get_method_entries(
    first_me_addr: Address,
    num_of_method_entry_refs: int,
    settings: ArchitectureSpecificSettings,
    info: MdtMeInfo,
) -> MdtMeInfo:
    """
    Given an instance of an MdtMeInfo dataclass, grab each method entry address and prepare MeInfo
    dataclass instances for each of them.
    """
    for i in range(num_of_method_entry_refs):
        check_cancel()

        current_method_entry_ref_field = first_me_addr.add(i * (settings.ptr_size + 4))
        try:
            current_method_entry_addr = read_ptr(current_method_entry_ref_field, settings.ptr_size)
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

        # extend with method entry address information
        current_info = get_method_entries(
            method_entry_refs_start_addr, num_of_method_entry_refs, settings, current_info
        )
        mapping.entries[vmt_addr] = current_info

    return mapping


def traverse_parameter_entries(
    first_parameter_entry_addr: Address,
    num_of_parameter_entries: int,
    settings: ArchitectureSpecificSettings,
) -> dict[Address, ParameterInfo]:
    """
    Traverse a sequence of ParamEntries and extract relevant RTTI and naming information.

    For each ParamEntry, this function reads and dereferences the RTTI address, resolves its
    namespace (if available), reads the associated Pascal-style parameter name, and collects
    the information in a structured dictionary.

    Parameters:
        first_parameter_entry_addr (ghidra.program.model.address.Address): Starting address of the first
            ParamEntry.
        num_of_parameter_entries (int): Number of ParamEntries to process.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        dict[ghidra.program.model.address.Address,ParamInfo]: Mapping from each ParamEntry's address
            to a dictionary containing the parameter's RTTI address, name, and namespace.
    """
    parameter_entries_info = {}

    current_addr = first_parameter_entry_addr

    for _ in range(num_of_parameter_entries):
        check_cancel()

        # grab information
        parameter_entry_addr = current_addr
        try:
            rtti = read_ptr(read_ptr(current_addr, settings.ptr_size), settings.ptr_size)
            rtti_namespace = traverse_rtti_object(rtti, settings)
        except Exception:
            rtti = None
            rtti_namespace = None
        parameter_name_addr = current_addr.add(settings.ptr_size + 2)
        parameter_name = read_pascal_str(parameter_name_addr)

        # store information
        parameter_entries_info[parameter_entry_addr] = ParameterInfo(
            rtti_addr=rtti, parameter_name=parameter_name, rtti_namespace=rtti_namespace
        )

        # next ParamEntry
        current_addr = parameter_name_addr.add(len(parameter_name) + 1 + 3)

    return parameter_entries_info


def extract_function_entry_point(
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


def extract_function_name(
    method_entry_addr: Address, settings: ArchitectureSpecificSettings
) -> str | None:
    """
    Extract the name of a function given a specific MethodEntry address.

    Parameters:
        method_entry_addr (ghidra.program.model.address.Address): Starting address of MethodEntry.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        str: The name of the function as a String and its length.
    """
    name_of_function_addr = method_entry_addr.add(settings.ptr_size + 2)
    try:
        function_name = read_pascal_str(name_of_function_addr)
        return function_name
    except MemoryAccessException:
        warning(f"Grab of nameOfFunctionAddr failed. Skipping ME: {method_entry_addr}.")
        return None


def extract_return_type(
    method_entry_addr: Address, function_name_len: int, settings: ArchitectureSpecificSettings
) -> tuple[Address, str] | tuple[None, None]:
    """
    Extract the return type of a function given a specific MethodEntry address.

    Parameters:
        method_entry_addr (ghidra.program.model.address.Address): Starting address of MethodEntry.
        function_name_len (int): The length of the function name preceeding the return type
            information.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        tuple(ghidra.program.model.address.Address,str): The address of the RTTI return type and its
            String represenation (=return type name).
    """
    all_zero_addr = convert_to_addr("0x0")

    return_type_addr_field = method_entry_addr.add(function_name_len + settings.ptr_size + 4)
    try:
        dereferenced_return_type_addr = read_ptr(return_type_addr_field, settings.ptr_size)
        return_type_at = dereferenced_return_type_addr

        if dereferenced_return_type_addr == all_zero_addr:
            return return_type_at, "void"

        doubly_dereferenced_return_type_addr = read_ptr(
            dereferenced_return_type_addr, settings.ptr_size
        )
        return_type_str = traverse_rtti_object(doubly_dereferenced_return_type_addr, settings)
    except MemoryAccessException:
        warning(warning(f"Read of return type failed. Skipping ME: {method_entry_addr}."))
        return None, None

    return return_type_at, return_type_str


def extract_parameters(
    method_entry_addr: Address, function_name_len: int, settings: ArchitectureSpecificSettings
) -> dict[Address, ParameterInfo] | None:
    """
    Extract the parameter information of a function given a specific MethodEntry address.

    Parameters:
        method_entry_addr (ghidra.program.model.address.Address): Starting address of MethodEntry.
        function_name_len (int): The length of the function name preceeding the return type
            information.
        settings (ArchitectureSpecificSettings): A dataclass instance holding architecture settings.

    Returns:
        dict[ghidra.program.model.address.Address,ParamInfo]: Mapping from each ParamEntry's address
            to a dictionary containing the parameter's RTTI address, name, and namespace.
    """
    memory_interface = currentProgram.getMemory()

    num_of_parameter_entries_field = method_entry_addr.add(
        function_name_len + 2 * settings.ptr_size + 6
    )
    num_of_parameter_entries = memory_interface.getByte(num_of_parameter_entries_field) & 0xFF

    first_parameter_entry_field = num_of_parameter_entries_field.add(2)
    # address outside the .text section => false positive
    if not (
        settings.text_block_start_addr <= first_parameter_entry_field <= settings.text_block_end_addr
    ):
        return None

    return traverse_parameter_entries(first_parameter_entry_field, num_of_parameter_entries, settings)


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
                function_entry_point = extract_function_entry_point(method_entry_addr, settings)
            except MemoryAccessException:
                warning(f"Read of func entry point failed. Skipping ME: {method_entry_addr}.")
                continue
            # Delphi executables often contain a large concatenation of addresses at the very
            # end of the .text section -> falsely detected as a valid VMT
            except AddressOutOfBoundsException:
                break

            function_name = extract_function_name(method_entry_addr, settings)
            if not function_name:
                continue

            return_type_addr, return_type_str = extract_return_type(
                method_entry_addr, len(function_name) + 1, settings
            )
            if not (return_type_addr or return_type_str):
                continue

            params = extract_parameters(method_entry_addr, len(function_name) + 1, settings)
            if not params:
                del vmt_mdt_top_info.entries[vmt]
                break

            # store gathered information
            method_entry_info = MeInfo(
                function_entry_point=function_entry_point,
                function_name=function_name,
                return_type_at=return_type_addr,
                return_type_str=return_type_str,
                parameter_entries=params,
            )
            method_entries_info.method_entries[method_entry_addr] = method_entry_info

        # store information only if the loop didn't break (= all MethodEntries of MDT are valid)
        else:
            vmt_mdt_top_info.entries[vmt] = method_entries_info

    debug(f"Symbolic information after traverse_method_entries(): {vmt_mdt_top_info}")
    return vmt_mdt_top_info


###################################################################################################
#    PARSING LOGIC - needed for processing tempaltes                                              #
###################################################################################################
class RecursiveDescentParser:
    """
    Given a dot separated namespace string, upon calling the class method 'parse_fqn()', return the
    parts of the namespace string in hierarchically decending order. This parsing methodology is
    template-aware. Sadly, due to visualization bugs in Ghidra's decompilation view, template names
    which are longer than 10 characters are not shown correctly in decompiler view.

    EBNF-Grammar:
        fqn = namespace , { "." , namespace } , [ template ] ;
        template = "<" , fqn { "," , fqn } , ">" ;
        namespace = letter | "_" , { letter | digit | "_" } ;
        letter = "A" ... "Z" | "a" ... "z" ;
        digit = "0" ... "9" ;
    """

    def __init__(self, input_string: str) -> None:
        self.string = input_string
        self.pos = 0

    def _peek(self) -> Optional[str]:
        return self.string[self.pos] if self.pos < len(self.string) else None

    def _consume(self, expected_char: Optional[str] = None) -> None:
        peeked_char = self._peek()
        if expected_char and expected_char != peeked_char:
            raise ValueError(f"Unexpected character during parsing: {self.string[self.pos]=}.")
        self.pos += 1

    # fqn = namespace , { "." , namespace } , [ template ] ;
    def parse_fqn(self, trim_mode: bool = False) -> tuple[list[str], str]:
        namespaces = [self._parse_namespace()]
        while self._peek() == ".":
            self._consume(".")
            namespaces.append(self._parse_namespace())

        transmuted_fqn = namespaces[-1] if trim_mode else ".".join(namespaces)

        if self._peek() == "<":
            trimmed_template = self._parse_template()
            namespaces[-1] += trimmed_template
            transmuted_fqn += trimmed_template

        return namespaces, transmuted_fqn

    # template = "<" , fqn { "," , fqn } , ">" ;
    def _parse_template(self) -> str:
        self._consume("<")
        _, trimmed_namespace = self.parse_fqn(
            trim_mode=True if not SHOW_ENTIRE_TEMPLATE_NAMESPACES else False
        )
        while self._peek() == ",":
            self._consume(",")
            _, next_trimmed_namespace = self.parse_fqn(
                trim_mode=True if not SHOW_ENTIRE_TEMPLATE_NAMESPACES else False
            )
            trimmed_namespace += "," + next_trimmed_namespace
        self._consume(">")

        return "<" + trimmed_namespace + ">"

    # namespace = letter | "_" , { letter | digit } ;
    def _parse_namespace(self) -> str:
        namespace_start_pos = self.pos
        if not self._peek().isalpha() and not self._peek() == "_":
            raise ValueError(
                f"First part of namespace is not alphabetical or underscore: "
                f"{self.string[self.pos]=}, {self.string=}."
            )
        self._consume()
        while self._peek() is not None and (self._peek().isalnum() or self._peek() == "_"):
            self._consume()
        return self.string[namespace_start_pos : self.pos]


###################################################################################################
#    MAIN LOGIC - TRANSFORMATION FUNCTIONS                                                        #
###################################################################################################
def prepare_namespace(namespace_str: str) -> Namespace:
    """
    Given a full namespace as a dot separated string, create each namespace according to the string.

    Returns the deepest namespace object in the string defined hierarchy.
    """
    symbol_table = currentProgram.getSymbolTable()
    parent_namespace = currentProgram.getGlobalNamespace()

    parser = RecursiveDescentParser(namespace_str)
    parts, _ = parser.parse_fqn()

    for part in parts:
        check_cancel()
        try:
            parent_namespace = symbol_table.getOrCreateNameSpace(
                parent_namespace, part, SourceType.USER_DEFINED
            )
        except InvalidInputException:
            return None

    return parent_namespace


def add_virtual_data_type(
    data_type: DataType,
    vmt_addr: Address,
    data_type_name: str,
    settings: ArchitectureSpecificSettings,
) -> None:
    """
    Extract virtual function information from VMT base addresses and create new structs (named with
    prefix "VT_") into Ghidra's data type manager containing said information.
    """
    if VT_CREATION is False:
        return

    data_types = currentProgram.getDataTypeManager()
    ptr_size = settings.ptr_size
    vt_data_type_name = "VT_" + data_type_name
    data_type_comment = "A pointer to the corresponding VT structure."
    vt_data_type_comment = "Recovered by DelphiReSym."

    # insert virtual functions
    vt_data_type = StructureDataType(CategoryPath("/"), vt_data_type_name, 0)
    for i in range(11, 22):  # TODO 64 bit support for those weird three addresses?
        function_address = read_ptr(vmt_addr.add(ptr_size * i), ptr_size)
        function = getFunctionAt(function_address)
        if function is None:
            function = createFunction(function_address, None)
        vt_data_type.insertAtOffset(
            ptr_size * i,
            PointerDataType(function.getSignature()),
            ptr_size,
            getFunctionAt(function_address).getName(),
            vt_data_type_comment,
        )

    vt_data_type = data_types.addDataType(
        vt_data_type, DataTypeConflictHandler.REPLACE_HANDLER
    )
    vt_pointer_data_type = PointerDataType(vt_data_type)

    if data_type.getNumComponents() > 0:
        data_type.replace(
            0, vt_pointer_data_type, ptr_size, vt_data_type_name, data_type_comment
        )
    else:
        data_type.add(
            vt_pointer_data_type, ptr_size, vt_data_type_name, data_type_comment
        )


class DataTypeInformation(NamedTuple):
    data_type: DataType
    namespace: Namespace


def prepare_data_type(
    type_string: str,
    vmt_addr: Optional[Address] = None,
    settings: Optional[ArchitectureSpecificSettings] = None,
) -> DataTypeInformation:
    """
    Given a dot-separated string representation of the form NAMESPACE.CLASS_NAME, create a class in
    the given namespace and return a NamedTuple containing the created datatype and namespace.
    Alternatively, returns a Ghidra internal datatype, if CLASS_NAME can be mapped directly to one.
    """
    global data_type_mapping
    data_types = currentProgram.getDataTypeManager()

    # TODO: remove later, debugging purposes only
    if "." not in type_string:
        types.add(type_string)

    if type_string in data_type_mapping:
        # ghidra built-in simple datatypes
        final_data_type = data_type_mapping[type_string]()
        namespace_obj = currentProgram.getGlobalNamespace()
    else:
        # create base datatype and virtual (vt) datatype
        namespace_obj = prepare_namespace(type_string)
        class_namespace = namespace_obj.getParentNamespace()
        class_name = namespace_obj.getName()
        try:
            createClass(class_namespace, class_name)
        except DuplicateNameException:
            pass

        data_type_path = CategoryPath(
            "/" + class_namespace.getName(True).replace("::", "/")
        )
        data_type = StructureDataType(data_type_path, class_name, 0)
        registered_data_type = data_types.addDataType(
            data_type,
            DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER,
        )

        if vmt_addr:
            add_virtual_data_type(registered_data_type, vmt_addr, class_name, settings)

        final_data_type = PointerDataType(registered_data_type)

    return DataTypeInformation(final_data_type, namespace_obj)


def apply_function_names(function_entry_point: Address, function_name: str | None) -> int:
    """
    Apply function name information for a specific function.

    Returns 1 on a success or 0 if no function name was applied.
    """
    function_manager = currentProgram.getFunctionManager()
    function = function_manager.getFunctionAt(convert_to_addr(function_entry_point))

    # if ghidra doesn't recognize this address already as a function
    if not function:
        # creating via the light-weight FlatProgramAPI function sets a name automatically
        function = createFunction(convert_to_addr(function_entry_point), function_name)
        # function could not be created for some reason, hence skip its symbol recovery
        if function is None:
            return 0
    else:
        # if function is already been known to ghidra, replace its name
        function.setName(function_name, SourceType.USER_DEFINED)

    return 1


def apply_namespaces(function_entry_point: Address, namespace: Namespace) -> int:
    """
    Apply namespace information for a specific function.

    Returns 1 on a success or 0 if no namespace was applied.
    """
    function_manager = currentProgram.getFunctionManager()
    function = function_manager.getFunctionAt(convert_to_addr(function_entry_point))

    if namespace is not None:
        try:
            function.setParentNamespace(namespace)
            return 1
        except Exception as e:
            warning(f"Caught exception: {e}\n...for {namespace}. Please notify the author.")
            return 0


def apply_return_types(function_entry_point: Address, return_type_str: str) -> int:
    """
    Apply return type information for a specific function.

    Returns 1 on a success or 0 if no function name was applied.
    """
    if return_type_str is None:
        return 0

    function_manager = currentProgram.getFunctionManager()
    function = function_manager.getFunctionAt(convert_to_addr(function_entry_point))

    return_data_type_object = prepare_data_type(return_type_str).data_type
    function.setReturnType(return_data_type_object, SourceType.USER_DEFINED)
    return 1


def apply_parameter_tuples(
    function_entry_point: Address, parameter_entries: dict[Address, ParameterInfo], namespace: str
) -> int:
    """
    Apply parameter tuple (parameter type, parameter data type) information for a specific
    function given ParamInfo data.

    Returns 1 on a success or 0 if no function name was applied.
    """
    # prepare parameters
    params = []
    for _, parameter_info in parameter_entries.items():
        rtti_name = (
            namespace
            if parameter_info.rtti_namespace is None or parameter_info.parameter_name == "Self"
            else parameter_info.rtti_namespace
        )
        final_data_type = prepare_data_type(rtti_name).data_type
        param = ParameterImpl(parameter_info.parameter_name, final_data_type, currentProgram)
        params.append(param)

    # replace parameters
    function_manager = currentProgram.getFunctionManager()
    function = function_manager.getFunctionAt(convert_to_addr(function_entry_point))
    try:
        function.replaceParameters(
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.USER_DEFINED,
            params,
        )
    # skip in case of invalid symbol names
    except InvalidInputException:
        return 0

    return 1


def apply_symbols(all_symbol_info: VmtMdtMapping, settings: ArchitectureSpecificSettings) -> dict[str, int]:
    """
    Handles the actual symbol name recovering, given all previously gathered information.

    For every found VMT, the function iterates over every MethodEntry information and attempts to
    apply data like its name, parameter and return types and parameter names in Ghidra.

    Returns: Counts of successfully recovered VMTs, FQNs, return types and parameter information.
    """
    apply_count = {"vmt": 0, "function": 0, "fqn": 0, "return": 0, "parameter_set": 0}

    for vmt, mdt_me_info in all_symbol_info.entries.items():
        debug(f"[7/8] Currently processing symbol information for VMT @ {vmt} ...")
        apply_count["vmt"] += 1

        if mdt_me_info.namespace is None or not mdt_me_info.namespace:
            continue
        namespace = prepare_data_type(mdt_me_info.namespace, vmt, settings).namespace

        for _, me_info in mdt_me_info.method_entries.items():
            check_cancel()
            entry = me_info.function_entry_point

            if not apply_function_names(entry, me_info.function_name):
                continue
            apply_count["function"] += 1

            if apply_namespaces(entry, namespace):
                apply_count["fqn"] += 1

            if apply_return_types(entry, me_info.get_return_type_string()):
                apply_count["return"] += 1

            if apply_parameter_tuples(
                entry, me_info.parameter_entries, mdt_me_info.namespace
            ):
                apply_count["parameter_set"] += 1

    return apply_count


###################################################################################################
#    MAIN LOGIC - ACTUAL MAIN                                                                     #
###################################################################################################
def print_final_stats(
    original_function_count: int,
    total_function_count: int,
    vmt_addresses: list[Address],
    recovery_counts: dict[str, int],
) -> None:
    """
    Print after-execution-statistics, including function counts, VMT counts and percentages of
    recovered symbolic information.
    """
    info(f"[8/8] Statistics: Pre-execution number of functions: {original_function_count}")
    info(f"[8/8] Statistics: Post-execution number of functions: {total_function_count}")
    info(f"[8/8] Statistics: Number of VMTs found: {len(vmt_addresses)}")
    info(
        f"[8/8] Statistics: Number of symbol recovered VMTs: {recovery_counts['vmt']}, yielding "
        f"{recovery_counts['vmt']/len(vmt_addresses)*100:.2f}% of all found VMTs."
    )
    info(
        f"[8/8] Statistics: Number of symbol recovered functions: {recovery_counts['function']}, "
        f"yielding {recovery_counts['function'] / total_function_count * 100:.2f}% of all functions; "
        f"or {recovery_counts['function'] / original_function_count * 100:.2f}% when using "
        "pre-execution function count."
    )
    info(
        f"[8/8] Statistics: Number of applied FQNs: {recovery_counts['fqn']}, yielding "
        f"{recovery_counts['fqn'] / total_function_count * 100:.2f}% of all functions; or "
        f"{recovery_counts['fqn'] / original_function_count * 100:.2f}% when using pre-execution "
        "function count."
    )
    info(
        f"[8/8] Statistics: Number of applied return types: {recovery_counts['return']}, yielding "
        f"{recovery_counts['return'] / total_function_count * 100:.2f}% of all functions; or "
        f"{recovery_counts['return'] / original_function_count * 100:.2f}% when using pre-execution "
        "function count."
    )
    info(
        f"[8/8] Statistics: Number of applied parameter sets: {recovery_counts['parameter_set']}, "
        f"yielding {recovery_counts['parameter_set'] / total_function_count * 100:.2f}% of all "
        f"functions; or {recovery_counts['parameter_set'] / original_function_count * 100:.2f}% when "
        "using pre-execution function count."
    )

    return


def main() -> None:
    """
    Main function orchestrating the analysis and recovery of symbolic information from an
    executable's VMTs, MDTs and RTTI_Classes.
    """
    original_function_count = currentProgram.getFunctionManager().getFunctionCount()

    memory_interface = currentProgram.getMemory()
    text_section = get_text_section(memory_interface)
    settings = get_architecture_settings(text_section)

    info("[1/8] Starting to scan for candidate VMTs & performing sanity checks...")
    vmt_addresses = find_vmts(settings)

    info("[2/8] Grabbing the MDT of every found VMT...")
    vmt_mdt_relations = get_vmt_field_addresses(vmt_addresses, settings, settings.mdt_offset)

    info("[3/8] Grabbing the RTTI_Class of every found VMT...")
    vmt_rtti_relations = get_vmt_field_addresses(vmt_addresses, settings, settings.rtti_offset)

    info("[4/8] Grabbing the MethodEntries of every found MDT...")
    vmt_mdt_top_level = traverse_mdt_top_level(vmt_mdt_relations, settings)

    info("[5/8] Extracting information of all MethodEntries of every found MDT...")
    vmt_mdt_symbols = traverse_method_entries(vmt_mdt_top_level, settings)

    info("[6/8] Extracting the RTTI namespaces for every VMT/MDT...")
    all_symbols = add_namespace_information(vmt_rtti_relations, vmt_mdt_symbols, settings)

    info("[7/8] Reconstructing all symbol names...")
    recovery_counts = apply_symbols(all_symbols, settings)

    total_function_count = currentProgram.getFunctionManager().getFunctionCount()
    print_final_stats(original_function_count, total_function_count, vmt_addresses, recovery_counts)
    info("[8/8] Finished.")

    # the following two lines are for debugging purposes only
    global types
    debug(str(types))


if pyghidra.started():
    if ENABLE_PROFILING:
        import yappi
        yappi.set_clock_type("wall")
        yappi.start()
    else:
        yappi = None
    try:
        main()
    except MonitorCancel:
        pass
    except Exception:
        raise
    finally:
        if yappi is not None:
            import pathlib
            path = pathlib.Path(__file__)
            path = path.parent / f"{path.stem}.perf"
            info(f"profiling information has been written to: {path.absolute()}")
            stats = yappi.get_func_stats()
            stats.save(path, type="CALLGRIND")
