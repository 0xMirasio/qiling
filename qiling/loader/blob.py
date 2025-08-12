#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
# Added support for raw binary blob emulation
#    Kelly Patterson - Cisco Talos
#         Copyright (C) 2025 Cisco Systems Inc

from qiling import Qiling
from qiling.loader.loader import QlLoader, Image
from qiling.os.memory import QlMemoryHeap


class QlLoaderBLOB(QlLoader):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

    def run(self):
        if self.ql.os.profile.has_section("BLOB_RAW"):
            # For raw binary blobs, user will handle memory mapping
            self.load_address = int(self.ql.os.profile.get("BLOB_RAW", "load_address"), 16)
            image_size = int(self.ql.os.profile.get("BLOB_RAW", "image_size"), 16)
            image_name = self.ql.os.profile.get("BLOB_RAW", "image_name", fallback="blob.raw")
            self.images.append(Image(self.load_address, self.load_address+image_size, image_name))  # used to collect coverage
        else:
            self.load_address = self.ql.os.load_address
            self.entry_point = self.ql.os.entry_point

            code_begins = self.load_address
            code_size = self.ql.os.code_ram_size
            code_ends = code_begins + code_size

            self.ql.mem.map(code_begins, code_size, info="[code]")
            self.ql.mem.write(code_begins, self.ql.code)

            # allow image-related functionalities
            self.images.append(Image(code_begins, code_ends, 'blob_code'))

            # FIXME: heap starts above end of ram??
            # FIXME: heap should be allocated by OS, not loader
            heap_base = code_ends
            heap_size = int(self.ql.os.profile.get("CODE", "heap_size"), 16)
            self.ql.os.heap = QlMemoryHeap(self.ql, heap_base, heap_base + heap_size)

            # FIXME: stack pointer should be a configurable profile setting
            self.ql.arch.regs.arch_sp = code_ends - 0x1000
