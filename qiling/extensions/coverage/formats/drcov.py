#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from ctypes import Structure, c_uint32, c_uint16
from typing import TYPE_CHECKING, BinaryIO

from .base import QlBaseCoverage


if TYPE_CHECKING:
    from qiling import Qiling


# Adapted from https://www.ayrx.me/drcov-file-format
class bb_entry(Structure):
    _fields_ = [
        ("start",  c_uint32),
        ("size",   c_uint16),
        ("mod_id", c_uint16)
    ]


class QlDrCoverage(QlBaseCoverage):
    """
    Collects emulated code coverage and formats it in accordance with the DynamoRIO based
    tool drcov: https://dynamorio.org/dynamorio_docs/page_drcov.html

    The resulting output file can later be imported by coverage visualization tools such
    as Lighthouse: https://github.com/gaasedelen/lighthouse
    """

    FORMAT_NAME = "drcov"

    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.drcov_version = 2
        self.drcov_flavor = 'drcov'
        self.basic_blocks = []
        self.bb_callback = None

    def activate(self) -> None:
        self.bb_callback = self.ql.hook_block(self.block_callback)

    def deactivate(self) -> None:
        if self.bb_callback:
            self.ql.hook_del(self.bb_callback)

    def dump_coverage(self, coverage_file: str) -> None:
        def __write_line(bio: BinaryIO, line: str) -> None:
            bio.write(f'{line}\n'.encode())

        with open(coverage_file, "wb") as cov:
            __write_line(cov, f"DRCOV VERSION: {self.drcov_version}")
            __write_line(cov, f"DRCOV FLAVOR: {self.drcov_flavor}")
            __write_line(cov, f"Module Table: version {self.drcov_version}, count {len(self.ql.loader.images)}")
            __write_line(cov, "Columns: id, base, end, entry, checksum, timestamp, path")

            for mod_id, mod in enumerate(self. ql.loader.images):
                __write_line(cov, f"{mod_id}, {mod.base}, {mod.end}, 0, 0, 0, {mod.path}")

            __write_line(cov, f"BB Table: {len(self.basic_blocks)} bbs")

            for bb in self.basic_blocks.values():
                cov.write(bytes(bb))
