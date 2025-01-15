#!/usr/bin/env python3

"""
Predefined instruction substitution patterns.
Each pattern is a lambda function that generates equivalent instructions.
"""

SUBSTITUTIONS = {
    "mov": [
        lambda dst, src: f"push {src}\npop {dst}",
        lambda dst, src: f"xor {dst}, {dst}\nadd {dst}, {src}",
        lambda dst, src: f"xchg {dst}, {src}"  # Only for register-register
    ],
    "xor": [
        lambda dst, src: f"push {dst}\nnot {dst}\nand {dst}, {src}\nnot {dst}\npop {dst}",
        lambda dst, src: f"sub {dst}, {dst}\nsub {dst}, {src}\nneg {dst}"
    ],
    "add": [
        lambda dst, src: f"sub {dst}, -{src}",
        lambda dst, src: "\n".join([f"inc {dst}"] * int(src)) if src.isdigit() and int(src) <= 4 else f"add {dst}, {src}",
        lambda dst, src: f"neg {dst}\nsub {dst}, {src}\nneg {dst}"
    ],
    "sub": [
        lambda dst, src: f"add {dst}, -{src}",
        lambda dst, src: "\n".join([f"dec {dst}"] * int(src)) if src.isdigit() and int(src) <= 4 else f"sub {dst}, {src}"
    ],
    "and": [
        lambda dst, src: f"push {dst}\nnot {dst}\nor {dst}, not {src}\nnot {dst}\npop {dst}"
    ],
    "push": [
        lambda reg: f"mov [esp-4], {reg}\nsub esp, 4"
    ],
    "pop": [
        lambda reg: f"mov {reg}, [esp]\nadd esp, 4"
    ]
} 