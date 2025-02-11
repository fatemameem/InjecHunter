#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

# Import necessary Ghidra classes
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.listing import Instruction, Function
from ghidra.program.model.symbol import RefType, Symbol
from ghidra.program.model.address import Address
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.lang import Register
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor
import os

# Initialize FlatProgramAPI for easier program navigation
flat_api = FlatProgramAPI(currentProgram)

# Define a list of suspicious API calls
suspicious_api_calls = [
    "CreateProcess", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "lstrcatA",
    "CreateRemoteThread", "NtCreateThreadEx", "SetThreadContext", "ResumeThread",
    "NtUnmapViewOfSection", "NtCreateSection", "NtCreateProcessEx", "VirtualProtectEx",
    "FlushInstructionCache", "OpenThread", "SuspendThread", "GetThreadContext",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "NtLoadDriver", "NtSetSystemInformation",
    "SetWindowsHookExA", "SetWindowsHookExW", "NtMapViewOfSection", "NtResumeThread",
    "GetCurrentDirectoryA", "GetModuleHandleA", "CloseHandle",
    "AllocConsole", "FindWindowA", "ShowWindow", "GetMessageA", "UnhookWindowsHookEx",
    "GetCurrentProcess", "OpenProcessToken", "LookupPrivilegeValueA", "CloseHandle", "AdjustTokenPrivileges",
]

# Define sequences of suspicious API calls indicative of DLL injection
suspicious_sequences = [
    ["GetCurrentDirectoryA", "lstrcatA", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "GetModuleHandleA", "GetProcAddress", "CreateRemoteThread"],
    ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "GetProcAddress", "CreateRemoteThread"],
    ["VirtualAllocEx", "WriteProcessMemory", "GetProcAddress", "CreateRemoteThread"],
    ["GetThreadContext", "GetModuleHandleA", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
    ["AllocConsole", "FindWindowA", "ShowWindow", "GetModuleHandleA", "SetWindowsHookExA", "GetMessageA", "UnhookWindowsHookEx"],
    ["GetCurrentProcess", "OpenProcessToken", "LookupPrivilegeValueA", "CloseHandle", "AdjustTokenPrivileges", "LoadLibraryA", "GetProcAddress", "OpenProcess", "CreateRemoteThread" ]
]

def find_all_suspicious_api_calls():
    program = currentProgram
    listing = program.getListing()
    symbol_table = program.getSymbolTable()
    api_addresses = {}

    suspicious_api_set = set(suspicious_api_calls)
    for symbol in symbol_table.getExternalSymbols():
        api_name = symbol.getName()
        if api_name in suspicious_api_set:
            refs = symbol.getReferences()
            call_addresses = []
            for ref in refs:
                if ref.getReferenceType().isCall():
                    call_address = ref.getFromAddress().getOffset()
                    if api_name not in api_addresses:
                        api_addresses[api_name] = []
                    api_addresses[api_name].append(call_address)
    return api_addresses

def collect_instructions():
    instructions = []
    listing = currentProgram.getListing()
    func_manager = currentProgram.getFunctionManager()
    funcs = func_manager.getFunctions(True)

    for func in funcs:
        instr_iter = listing.getInstructions(func.getBody(), True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            instructions.append(instr)

    return instructions

def find_suspicious_sequences(api_addresses, instructions, max_gap=100):
    address_to_api = {}
    for api_name, addresses in api_addresses.items():
        for addr in addresses:
            address_to_api[addr] = api_name

    api_call_sequence = []
    instr_addresses = []
    for idx, instr in enumerate(instructions):
        addr = instr.getAddress().getOffset()
        instr_addresses.append(addr)
        if addr in address_to_api:
            api_call_sequence.append((idx, addr, address_to_api[addr], instr))

    detected_sequences = []

    for sequence in suspicious_sequences:
        seq_len = len(sequence)
        for i, (start_idx, start_addr, api_name, instr) in enumerate(api_call_sequence):
            if api_name != sequence[0]:
                continue

            idx_seq = 1
            current_instr_idx = start_idx

            while idx_seq < seq_len and current_instr_idx < len(instructions) - 1:
                gap = 0
                found = False
                while gap < max_gap and current_instr_idx + 1 < len(instructions):
                    current_instr_idx += 1
                    gap += 1
                    addr = instr_addresses[current_instr_idx]
                    if addr in address_to_api:
                        api_name_candidate = address_to_api[addr]
                        if api_name_candidate == sequence[idx_seq]:
                            idx_seq += 1
                            found = True
                            break
                        elif api_name_candidate == sequence[idx_seq - 1]:
                            # Skip repeated occurrences of the current API in the sequence
                            continue
                if not found:
                    break

            if idx_seq == seq_len:
                detected_sequences.append(sequence)
                # Once a sequence is found, no need to continue searching for this sequence
                # If you want to find all occurrences, you can remove this break
                break

    return detected_sequences

def main():
    try:
        api_addresses = find_all_suspicious_api_calls()
        instructions = collect_instructions()
        detected_sequences = find_suspicious_sequences(api_addresses, instructions, max_gap=150)

        # Initialize detection result to 0 (no suspicious sequences found by default)
        detected = 0
        if detected_sequences:
            detected = 1

        # Retrieve the program name (executable name)
        program_name = os.path.basename(currentProgram.getExecutablePath())

        # Print CSV format: <program_name>,<detection_result>
        print("{},{}".format(program_name, detected))

    except Exception as e:
        print("Error during analysis: {}".format(e))

# Execute the function
main()
