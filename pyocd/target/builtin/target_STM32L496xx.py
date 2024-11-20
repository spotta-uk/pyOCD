# pyOCD debugger
# Copyright (c) 2024 spotta
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile

class DBGMCU:
    CR = 0xE0042004
    CR_VALUE = 0x7 # DBG_STANDBY | DBG_STOP | DBG_SLEEP

    APB1FZR1 = 0xE0042008
    APB1FZR1_VALUE = 0x86e01c3f

    APB1FZR2 = 0xE004200C
    APB1FZR2_VALUE = 0x00000022

    APB2FZR = 0xE0042010
    APB2FZR_VALUE = 0x00072800

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x8f4ff3bf, 0x487a4770, 0x497a6800, 0x0d000500, 0xd0051840, 0xd003282d, 0xd001282f, 0x47702001,
    0x47702000, 0x6a004874, 0x0fc00280, 0xb5004770, 0xf7ff4602, 0x2801ffe8, 0xf7ffd108, 0x2801fff3,
    0x486ed104, 0xd3014282, 0xbd002001, 0xbd002000, 0x4602b500, 0xffd7f7ff, 0xd0022801, 0x0d8002d0,
    0x4967bd00, 0x40080ad0, 0xd5f90311, 0x300130ff, 0x4861bd00, 0x60814963, 0x60814963, 0x60012100,
    0x61014962, 0x03c06a00, 0x4862d406, 0x60014960, 0x60412106, 0x60814960, 0x47702000, 0x49562001,
    0x614807c0, 0x47702000, 0x47702001, 0x49574852, 0x13c16101, 0x69416141, 0x04122201, 0x61414311,
    0x4a544956, 0x6011e000, 0x03db6903, 0x2100d4fb, 0x46086141, 0xb5104770, 0xf7ff4604, 0x4603ffa8,
    0xf7ff4620, 0x4944ffb5, 0x610c4c48, 0x02d800c2, 0x43021c92, 0x6948614a, 0x04122201, 0x61484310,
    0x8f4ff3bf, 0x4a434845, 0x6010e000, 0x03db690b, 0x2000d4fb, 0x69086148, 0xd0014020, 0x2001610c,
    0xb5f0bd10, 0xb0884b34, 0x611c4c38, 0x615c2400, 0xe059466e, 0x24014b30, 0x2908615c, 0x6813d315,
    0x68536003, 0xf3bf6043, 0x4c348f4f, 0x4b2a4d31, 0x602ce000, 0x03ff691f, 0x691bd4fb, 0x42234c2b,
    0x3008d13c, 0x32083908, 0x2300e03e, 0x7814e004, 0x1c52009d, 0x1c5b5174, 0xd3f8428b, 0x24ff2300,
    0x1a6d2508, 0x185fe003, 0x51f400bf, 0x429d1c5b, 0x9b01d8f9, 0x021b9900, 0x990218cb, 0x04099c03,
    0x19090624, 0x91001859, 0x99049b05, 0x18c9021b, 0x9c079b06, 0x0624041b, 0x18c9191b, 0x99009101,
    0x99016001, 0xf3bf6041, 0x4b0b8f4f, 0x691c2100, 0xd4fc03e4, 0x4c0d691b, 0xd0054223, 0x480b4906,
    0x20016108, 0xbdf0b008, 0xd1a32900, 0xe7f92000, 0xe0042000, 0xfffffbcb, 0x40022000, 0x08080000,
    0x000002ff, 0x45670123, 0xcdef89ab, 0x0000c3fa, 0x00005555, 0x40003000, 0x00000fff, 0x0000aaaa,
    0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000077,
    'pc_unInit': 0x200000a1,
    'pc_program_page': 0x20000127,
    'pc_erase_sector': 0x200000db,
    'pc_eraseAll': 0x200000b1,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000220,
    'begin_stack' : 0x20001a30,
    'end_stack' : 0x20000a30,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000230,
        0x20000630
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x220,
    'rw_start': 0x224,
    'rw_size': 0x4,
    'zi_start': 0x228,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}

class STM32L496xx(CoreSightTarget):
    
    VENDOR = "STMicroelectronics"
    MEMORY_MAP = MemoryMap(
        FlashRegion(name='flash', start=0x08000000, length=0x100000,
                        sector_size=0x800,
                        page_size=0x400,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(name='sram1',   start=0x20000000, length=0x40000),
        RamRegion(name='sram2',   start=0x20040000, length=0x10000)
        )
    
    def __init__(self, session):
        super(STM32L496xx, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("STM32L496.svd")
        
    def post_connect_hook(self):
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)
        self.write32(DBGMCU.APB1FZR1, DBGMCU.APB1FZR1_VALUE)
        self.write32(DBGMCU.APB1FZR2, DBGMCU.APB1FZR2_VALUE)
        self.write32(DBGMCU.APB2FZR, DBGMCU.APB2FZR_VALUE)


