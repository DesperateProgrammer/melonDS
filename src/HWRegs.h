/*
    Copyright 2016-2021 Arisotura

    This file is part of melonDS.

    melonDS is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    melonDS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with melonDS. If not, see http://www.gnu.org/licenses/.
*/

#ifndef HWREGS_H
#define HWREGS_H

/* Create cases for the address of the named 32 bit hw register for 32/16 or 8 
   Bit access */
#define HWREG32_CASES_32(addr)    case (addr & ~3):
#define HWREG32_CASES_16(addr)    case (addr & ~3):\
                                     case ((addr & ~3) + 2):
#define HWREG32_CASES_8(addr)     case (addr & ~3):\
                                     case ((addr & ~3) + 1):\
                                     case ((addr & ~3) + 2):\
                                     case ((addr & ~3) + 3):


/* SCFG */
#define HWREG_SCFG_BIOS               0x04004000
#define HWREG_SCFG_CLOCK              0x04004004
#define HWREG_SCFG_RST                0x04004006
#define HWREG_SCFG_EXT                0x04004008
#define HWREG_SCFG_MC                 0x04004010

/* NWRAM */
#define HWREG_NWRAM_MBK(n)            (0x04004040 + (n-1)*4)

/* NDMA */
#define HWREG_NDMA_CNT                0x040004100
#define HWREG_NDMA_SRC(n)             (0x040004104 + (n*0x1C))
#define HWREG_NDMA_DST(n)             (0x040004108 + (n*0x1C))
#define HWREG_NDMA_LEN(n)             (0x04000410C + (n*0x1C))
#define HWREG_NDMA_BLKLEN(n)          (0x040004110 + (n*0x1C))
#define HWREG_NDMA_TIMER(n)           (0x040004114 + (n*0x1C))
#define HWREG_NDMA_FILLDATA(n)        (0x040004118 + (n*0x1C))
#define HWREG_NDMA_CHANNELCNT(n)      (0x04000411C + (n*0x1C))

/* Camera */
#define HWREG_CAM_BASE                0x04004200

/* DSP */
#define HWREG_DSP_BASE                0x04004300



#endif