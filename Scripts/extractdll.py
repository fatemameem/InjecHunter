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
    "CloseHandle", "VirtualAlloc", "CreateProcessA", "CallNextHookEx"
]

# Define sequences of suspicious API calls indicative of DLL injection
suspicious_sequences = [
    ["GetCurrentDirectoryA", "lstrcatA", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "GetModuleHandleA", "GetProcAddress", "CreateRemoteThread"],
    
    ["CloseHandle", "CreateProcessA", "VirtualAlloc", "GetThreadContext", "GetModuleHandleA", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
    ["AllocConsole", "FindWindowA", "ShowWindow", "GetModuleHandleA", "SetWindowsHookExA", "GetMessageA", "UnhookWindowsHookEx", "CallNextHookEx"],
    ["GetCurrentProcess", "OpenProcessToken", "LookupPrivilegeValueA", "CloseHandle", "AdjustTokenPrivileges", "LoadLibraryA", "GetProcAddress", "OpenProcess", "CreateRemoteThread" ]

]

# Extracting system API calls and their addresses from the binary
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
                    call_addresses.append("0x{:08x}".format(call_address))
            if call_addresses:
                addresses_str = ", ".join(call_addresses)
                print("Suspicious API '{}' called at addresses: {}".format(api_name, addresses_str))

    return api_addresses

# Function to collect all instructions in the program
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

# Function to analyze variable assignments before a given instruction
def analyze_variable_assignments(instr):
    current_instr = instr.getPrevious()
    max_instructions = 20
    visited_instructions = set()

    while current_instr and max_instructions > 0:
        max_instructions -= 1
        if current_instr in visited_instructions:
            break
        visited_instructions.add(current_instr)
        mnem = current_instr.getMnemonicString()
        if mnem in ["MOV", "LEA"]:
            dest = current_instr.getOpObjects(0)
            src = current_instr.getOpObjects(1)
            if dest and src:
                print("  Potential variable assignment: {} <- {}".format(dest[0], src[0]))
        current_instr = current_instr.getPrevious()

# Function to find sequences of API calls
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

    print("\nAPI Call Sequence:")
    for idx, addr, api_name, instr in api_call_sequence:
        print("Index: {}, Address: 0x{:08x}, API: {}".format(idx, addr, api_name))

    detected_sequences = []
    used_indices = set()

    for sequence in suspicious_sequences:
        seq_len = len(sequence)
        print("\nSearching for sequence: {}".format(sequence))
        for i in range(len(api_call_sequence)):
            start_idx, start_addr, api_name, instr = api_call_sequence[i]
            if start_idx in used_indices:
                continue
            if api_name != sequence[0]:
                continue

            print("\nStarting potential sequence at index {} ({} at 0x{:08x})".format(i, api_name, start_addr))
            idx_seq = 1
            match = [(start_idx, start_addr, api_name, instr)]
            temp_used_indices = set([start_idx])

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
                        instr_candidate = instructions[current_instr_idx]
                        print("  Found API call: {} at 0x{:08x} (Index {})".format(api_name_candidate, addr, current_instr_idx))

                        # Modification: Only consider the next unique API in the sequence
                        if api_name_candidate == sequence[idx_seq]:
                            print("    API matches sequence at position {}: {}".format(idx_seq, api_name_candidate))
                            match.append((current_instr_idx, addr, api_name_candidate, instr_candidate))
                            temp_used_indices.add(current_instr_idx)
                            idx_seq += 1
                            found = True
                            break
                        elif api_name_candidate == sequence[idx_seq - 1]:
                            # Skip repeated occurrences of the current API in the sequence
                            print("    Skipping duplicate API: {}".format(api_name_candidate))
                if not found:
                    print("    Next API in sequence not found within max_gap")
                    print("  Incomplete sequence")
                    break

            if idx_seq == seq_len:
                print("  Complete sequence found")
                for idx_s, addr_s, api_name_s, instr_s in match:
                    if api_name_s == "VirtualAllocEx":
                        analyze_variable_assignments(instr_s)
                detected_sequences.append(match)
                used_indices.update(temp_used_indices)

    return detected_sequences

# Main function to extract and list suspicious API calls and sequences
def main():
    try:
        print("Extracting suspicious system API calls and their call sites...")

        api_addresses = find_all_suspicious_api_calls()
        if not api_addresses:
            print("No suspicious API calls found or there was an error during extraction.")
            return

        instructions = collect_instructions()
        print("\nAnalyzing for suspicious sequences...")
        detected_sequences = find_suspicious_sequences(api_addresses, instructions, max_gap=150)

        if detected_sequences:
            print("\nSuspicious sequences detected:")
            for seq in detected_sequences:
                print("Sequence:")
                for idx, addr, api_name, instr in seq:
                    print("  {} at address 0x{:08x}".format(api_name, addr))
                    if api_name == "VirtualAllocEx":
                        analyze_variable_assignments(instr)
                print("---")
        else:
            print("No suspicious sequences found.")

        print("\nAnalysis Complete.")

    except Exception as e:
        print("Error during analysis: {}".format(e))

# Execute the function
main()
