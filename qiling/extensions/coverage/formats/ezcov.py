#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from collections import namedtuple
from os.path import basename
from typing import TYPE_CHECKING, List

from .base import QlBaseCoverage


if TYPE_CHECKING:
    from qiling import Qiling


# Adapted from https://github.com/nccgroup/Cartographer/blob/main/EZCOV.md#coverage-data
class bb_entry(namedtuple('bb_entry', 'offset size mod_id')):
    def csvline(self):
        offset = '0x{:08x}'.format(self.offset)
        mod_id = f"[ {self.mod_id if self.mod_id is not None else ''} ]"
        return f"{offset},{self.size},{mod_id}\n"

class QlEzCoverage(QlBaseCoverage):
    """
    Collects emulated code coverage and formats it in accordance with the Cartographer Ghidra extension:
    https://github.com/nccgroup/Cartographer/blob/main/EZCOV.md

    The resulting output file can later be imported by coverage visualization tools such
    as Cartographer: https://github.com/nccgroup/Cartographer/
    """

    FORMAT_NAME = "ezcov"

    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.ezcov_version = 1
        self.ezcov_flavor = 'ezcov'
        self.basic_blocks: List[bb_entry]  = []
        self.bb_callback = None

    def block_callback(self, ql: Qiling, address: int, size: int):

    def activate(self) -> None:
        self.bb_callback = self.ql.hook_block(self.block_callback)

    def deactivate(self) -> None:
        if self.bb_callback:
            self.ql.hook_del(self.bb_callback)

    def dump_coverage(self, coverage_file: str) -> None:
        with open(coverage_file, "w") as cov:
            cov.write(f"EZCOV VERSION: {self.ezcov_version}\n")
            cov.write("# Qiling EZCOV exporter tool\n")
            for bb in self.basic_blocks:
                cov.write(bb.csvline())