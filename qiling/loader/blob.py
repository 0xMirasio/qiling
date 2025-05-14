#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.loader.loader import QlLoader, Image
from qiling.os.memory import QlMemoryHeap


class QlLoaderBLOB(QlLoader):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.load_address = 0

    def run(self):
        self.load_address = self.ql.os.entry_point      # for consistency

        code_begins = self.load_address
        code_size = self.ql.os.code_ram_size
        code_ends = code_begins + code_size

        self.ql.mem.map(code_begins, code_size, info="[code]")
        self.ql.mem.write(code_begins, self.ql.code)

        # allow image-related functionalities
        self.images.append(Image(code_begins, code_ends, 'blob_code'))

        # FIXME: heap starts above end of ram??
        heap_base = code_ends
        heap_size = int(self.ql.os.profile.get("CODE", "heap_size"), 16)
        self.ql.os.heap = QlMemoryHeap(self.ql, heap_base, heap_base + heap_size)

        self.ql.arch.regs.arch_sp = code_ends - 0x1000
