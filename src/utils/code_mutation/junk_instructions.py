#!/usr/bin/env python3

"""
Predefined groups of junk instructions that preserve register states.
Each group contains instructions that have no effect on program execution.
"""

JUNK_GROUPS = {
    'arithmetic': [
        "push eax\nadd eax, 0\nsub eax, 0\npop eax",
        "push ecx\nxor ecx, ecx\ninc ecx\ndec ecx\npop ecx",
        "push edx\nimul edx, edx, 1\npop edx"
    ],
    'logical': [
        "push eax\nand eax, 0xFFFFFFFF\npop eax",
        "push ebx\nxor ebx, ebx\nxor ebx, ebx\npop ebx",
        "push ecx\nor ecx, 0\npop ecx"
    ],
    'stack': [
        "pushfd\npopfd",
        "push eax\npush ebx\npop ebx\npop eax",
        "enter 0, 0\nleave"
    ],
    'flags': [
        "pushfd\ncmp eax, eax\npopfd",
        "pushfd\ntest esp, esp\npopfd",
        "pushfd\nbt eax, 0\npopfd"
    ]
} 