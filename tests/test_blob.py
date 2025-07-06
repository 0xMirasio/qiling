#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest

import sys
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.const import STRING, POINTER, SIZE_T


class BlobTest(unittest.TestCase):
    def test_uboot_arm(self):
        def my_getenv(ql: Qiling):
            env = {
                "ID": b"000000000000000",
                "ethaddr": b"11:22:33:44:55:66"
            }

            params = ql.os.resolve_fcall_params({'key': STRING})
            value = env.get(params["key"], b"")

            value_addr = ql.os.heap.alloc(len(value))
            ql.mem.write(value_addr, value)

            ql.arch.regs.r0 = value_addr
            ql.arch.regs.arch_pc = ql.arch.regs.lr

        def check_password(ql: Qiling):
            params = ql.os.resolve_fcall_params({
                'ptr1': POINTER,  # points to real password
                'ptr2': POINTER,  # points to user provided password
                'size': SIZE_T    # comparison length
            })

            ptr1 = params['ptr1']
            ptr2 = params['ptr2']
            size = params['size']

            real_password = ql.mem.read(ptr1, size)
            user_password = ql.mem.read(ptr2, size)

            self.assertSequenceEqual(real_password, user_password, seq_type=bytearray)

        def partial_run_init(ql: Qiling):
            # argv prepare
            ql.arch.regs.arch_sp -= 0x30
            arg0_ptr = ql.arch.regs.arch_sp
            ql.mem.write(arg0_ptr, b"kaimendaji")

            ql.arch.regs.arch_sp -= 0x10
            arg1_ptr = ql.arch.regs.arch_sp
            ql.mem.write(arg1_ptr, b"013f1f")

            ql.arch.regs.arch_sp -= 0x20
            argv_ptr = ql.arch.regs.arch_sp
            ql.mem.write_ptr(argv_ptr, arg0_ptr)
            ql.mem.write_ptr(argv_ptr + ql.arch.pointersize, arg1_ptr)

            ql.arch.regs.r2 = 2
            ql.arch.regs.r3 = argv_ptr

        print("ARM uboot bin")

        with open("../examples/rootfs/blob/u-boot.bin.img", "rb") as f:
            uboot_code = f.read()

        ql = Qiling(code=uboot_code[0x40:], archtype=QL_ARCH.ARM, ostype=QL_OS.BLOB, profile="profiles/uboot_bin.ql", verbose=QL_VERBOSE.DEBUG)

        imgbase = ql.loader.images[0].base

        ql.hook_address(my_getenv, imgbase + 0x13AC0)
        ql.hook_address(check_password, imgbase + 0x48634)

        partial_run_init(ql)

        ql.run(imgbase + 0x486B4, imgbase + 0x48718)

        del ql


if __name__ == "__main__":
    unittest.main()
