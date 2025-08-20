##############################################################################
# Added example for raw binary blob  
#    Kelly Patterson - Cisco Talos
#         Copyright (C) 2025 Cisco Systems Inc
##############################################################################
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.coverage import utils as cov_utils
from qiling.loader.loader import Image

BASE_ADDRESS = 0x10000000
CHECKSUM_FUNC_ADDR = BASE_ADDRESS + 0x8
END_ADDRESS = 0x100000ba
DATA_ADDR = 0xa0000000 # Arbitrary address for data
STACK_ADDR = 0xb0000000 # Arbitrary address for stack

# Python implementation of the checksum function being emulated
def checksum_function(input_data_buffer: bytes):
    expected_checksum_python = 0
    input_data_len = len(input_data_buffer)
    if input_data_len >= 1 and input_data_buffer[0] == 0xDE: # MAGIC_VALUE_1
        for i in range(min(input_data_len, 4)):
            expected_checksum_python += input_data_buffer[i]
        expected_checksum_python += 0x10
    elif input_data_len >= 2 and input_data_buffer[1] == 0xAD: # MAGIC_VALUE_2
        for i in range(input_data_len):
            expected_checksum_python ^= input_data_buffer[i]
        expected_checksum_python += 0x20
    else:
        for i in range(input_data_len):
            expected_checksum_python += input_data_buffer[i]
    expected_checksum_python &= 0xFF # Ensure it's a single byte
    return expected_checksum_python

def unmapped_handler(ql, type, addr, size, value):

    print(f"Unmapped Memory R/W, trying to access {hex(size)} bytes at {hex(addr)} from {hex(ql.arch.regs.pc)}")

def emulate_checksum_function(input_data_buffer: bytes):
    print(f"\n--- Testing with input: {input_data_buffer.hex()} ---")

    with open("rootfs/blob/example_raw.bin", "rb") as f:
        raw_code = f.read()

    ql = Qiling(code=raw_code, archtype=QL_ARCH.ARM, ostype=QL_OS.BLOB, profile="blob_raw.ql", verbose=QL_VERBOSE.DEBUG, thumb=True)

    # monkeypatch - Correcting the loader image name, used for coverage collection
    # Remove all images with name 'blob_code' that were created by the blob loader
    ql.loader.images = [img for img in ql.loader.images if img.path != 'blob_code']
    # Add image back with correct info
    ql.loader.images.append(Image(ql.loader.load_address, ql.loader.load_address + ql.os.code_ram_size, 'example_raw.bin'))


    input_data_len = len(input_data_buffer)

    # Map memory for the data and stack
    ql.mem.map(STACK_ADDR, 0x2000)
    ql.mem.map(DATA_ADDR, ql.mem.align_up(input_data_len + 0x100)) # Map enough space for data

    # Write input data
    ql.mem.write(DATA_ADDR, input_data_buffer)

    # Set up the stack pointer
    ql.arch.regs.sp = STACK_ADDR + 0x2000 - 4
    # Set up argument registers
    ql.arch.regs.r0 = DATA_ADDR
    ql.arch.regs.r1 = input_data_len

    # Set the program counter to the function's entry point
    ql.arch.regs.pc = CHECKSUM_FUNC_ADDR

    # Set the return address (LR) to a dummy address.
    ql.arch.regs.lr = 0xbebebebe

    ql.hook_mem_unmapped(unmapped_handler)
    #ql.debugger="gdb:127.0.0.1:9999"

    # Start emulation
    print(f"Starting emulation at PC: {hex(ql.arch.regs.pc)}")
    try:
        with cov_utils.collect_coverage(ql, 'drcov', 'output.cov'):
            ql.run(begin=CHECKSUM_FUNC_ADDR, end=END_ADDRESS)
    except Exception as e:
        print(f"Emulation error: {e}")

    print(f"Emulated checksum: {hex(ql.arch.regs.r0)}")

if __name__ == "__main__":
    data = b"\x01\x02\x03\x04\x05"  # Example input data
    emulate_checksum_function(data)
    print(hex(checksum_function(data)))