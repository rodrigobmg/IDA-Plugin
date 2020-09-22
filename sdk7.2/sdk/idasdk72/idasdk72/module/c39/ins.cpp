/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

instruc_t Instructions[] =
{
  { "",            0                       },
  { "ADC",         CF_USE1                 },
  { "ADD",         CF_USE1                 },
  { "ANC",         CF_USE1                 },
  { "AND",         CF_USE1                 },
  { "ANE",         CF_USE1                 },
  { "ARR",         CF_USE1                 },
  { "ASL",         0                       },
  { "ASR",         CF_USE1                 },
  { "BAR",         CF_USE1|CF_USE2|CF_USE3 },
  { "BAS",         CF_USE1|CF_USE2|CF_USE3 },
  { "BBR",         CF_USE1|CF_USE2|CF_USE3|CF_JUMP },
  { "BBS",         CF_USE1|CF_USE2|CF_USE3|CF_JUMP },
  { "BCC",         CF_USE1|CF_JUMP         },
  { "BCS",         CF_USE1|CF_JUMP         },
  { "BEQ",         CF_USE1|CF_JUMP         },
  { "BIT",         CF_USE1                 },
  { "BMI",         CF_USE1|CF_JUMP         },
  { "BNE",         CF_USE1|CF_JUMP         },
  { "BPL",         CF_USE1|CF_JUMP         },
  { "BRA",         CF_USE1|CF_JUMP|CF_STOP },
  { "BRK",         CF_STOP                 },
  { "BVC",         CF_USE1|CF_JUMP         },
  { "BVS",         CF_USE1|CF_JUMP         },
  { "CLC",         0                       },
  { "CLD",         0                       },
  { "CLI",         0                       },
  { "CLV",         0                       },
  { "CLW",         0                       },
  { "CMP",         CF_USE1                 },
  { "CPX",         CF_USE1                 },
  { "CPY",         CF_USE1                 },
  { "DCP",         CF_USE1|CF_CHG1         },
  { "DEC",         CF_USE1|CF_CHG1         },
  { "DEX",         0                       },
  { "DEY",         0                       },
  { "EOR",         CF_USE1                 },
  { "EXC",         CF_USE1                 },
  { "INC",         CF_USE1|CF_CHG1         },
  { "INI",         0                       },
  { "INX",         0                       },
  { "INY",         0                       },
  { "ISB",         CF_USE1|CF_CHG1         },
  { "JMP",         CF_USE1|CF_STOP|CF_JUMP },
  { "JPI",         CF_USE1|CF_STOP|CF_JUMP },
  { "JSB",         CF_USE1|CF_CALL         },
  { "JSR",         CF_USE1|CF_CALL         },
  { "LAB",         CF_USE1                 },
  { "LAE",         CF_USE1                 },
  { "LAI",         0                       },
  { "LAN",         0                       },
  { "LAX",         CF_USE1                 },
  { "LDA",         CF_USE1                 },
  { "LDX",         CF_USE1                 },
  { "LDY",         CF_USE1                 },
  { "LII",         0                       },
  { "LSR",         0                       },
  { "LXA",         CF_USE1                 },
  { "MPA",         0                       },
  { "MPY",         0                       },
  { "NEG",         CF_USE1                 },
  { "NOP",         0                       },
  { "NXT",         0                       },
  { "ORA",         CF_USE1                 },
  { "PHA",         0                       },
  { "PHI",         0                       },
  { "PHP",         0                       },
  { "PHW",         0                       },
  { "PHX",         0                       },
  { "PHY",         0                       },
  { "PIA",         0                       },
  { "PLA",         0                       },
  { "PLI",         0                       },
  { "PLP",         0                       },
  { "PLW",         0                       },
  { "PLX",         0                       },
  { "PLY",         0                       },
  { "PSH",         0                       },
  { "PUL",         0                       },
  { "RBA",         CF_USE1|CF_USE2         },
  { "RLA",         CF_USE1|CF_CHG1         },
  { "RMB",         CF_USE1|CF_USE2         },
  { "RND",         0                       },
  { "ROL",         0                       },
  { "ROR",         0                       },
  { "RRA",         CF_USE1|CF_CHG1         },
  { "RTI",         CF_STOP                 },
  { "RTS",         CF_STOP                 },
  { "SAX",         CF_CHG1                 },
  { "SBA",         CF_USE1|CF_USE2         },
  { "SBC",         CF_USE1                 },
  { "SBX",         CF_USE1                 },
  { "SEC",         0                       },
  { "SED",         0                       },
  { "SEI",         0                       },
  { "SHA",         CF_CHG1                 },
  { "SHS",         CF_CHG1                 },
  { "SHX",         CF_CHG1                 },
  { "SHY",         CF_CHG1                 },
  { "SLO",         CF_USE1|CF_CHG1         },
  { "SMB",         CF_USE1|CF_USE2|CF_CHG2 },
  { "SRE",         CF_USE1|CF_CHG1         },
  { "STA",         CF_CHG1                 },
  { "STI",         CF_USE1|CF_USE2         },
  { "STX",         CF_CHG1                 },
  { "STY",         CF_CHG1                 },
  { "TAX",         0                       },
  { "TAY",         0                       },
  { "TAW",         0                       },
  { "TIP",         0                       },
  { "TSX",         0                       },
  { "TWA",         0                       },
  { "TXA",         0                       },
  { "TXS",         0                       },
  { "TYA",         0                       }
};

CASSERT(qnumber(Instructions) == C39_last);
