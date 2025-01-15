#!/usr/bin/env python3

import random
from typing import List, Dict, Callable
from keystone import *
from capstone import *
from loguru import logger

from .junk_instructions import JUNK_GROUPS
from .instruction_substitutions import SUBSTITUTIONS
from .block_analysis import BasicBlock, identify_basic_blocks
from .dispatcher_generator import generate_flattened_code

class CodeMutation:
    """Handles code mutation and obfuscation techniques."""
    
    def __init__(self):
        """Initialize assembler and disassembler engines."""
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        
    def add_junk_instructions(self, original_code: bytes) -> bytes:
        """Add junk instructions that don't affect program flow."""
        try:
            # Disassemble original code
            instructions = list(self.cs.disasm(original_code, 0))
            modified_code = bytearray()
            
            for i, instr in enumerate(instructions):
                # Add original instruction
                modified_code.extend(instr.bytes)
                
                # Randomly decide whether to insert junk after this instruction
                if random.random() < 0.3:  # 30% chance of insertion
                    # Select random junk group and instruction
                    group = random.choice(list(JUNK_GROUPS.keys()))
                    junk = random.choice(JUNK_GROUPS[group])
                    
                    # Assemble junk instruction
                    try:
                        junk_bytes, _ = self.ks.asm(junk)
                        if junk_bytes:
                            modified_code.extend(bytes(junk_bytes))
                    except KsError as e:
                        logger.debug(f"Failed to assemble junk instruction: {e}")
                        continue
                    
                    # Add random NOPs after junk (0-3 NOPs)
                    nop_count = random.randint(0, 3)
                    nop_bytes, _ = self.ks.asm("nop" * nop_count)
                    if nop_bytes:
                        modified_code.extend(bytes(nop_bytes))
            
            return bytes(modified_code)
            
        except Exception as e:
            logger.error(f"Error in add_junk_instructions: {e}")
            return original_code
        
    def substitute_instructions(self, original_code: bytes) -> bytes:
        """Replace instructions with equivalent alternatives for obfuscation."""
        try:
            # Disassemble original code
            instructions = list(self.cs.disasm(original_code, 0))
            modified_code = bytearray()
            
            for instr in instructions:
                # Check if instruction can be substituted
                if instr.mnemonic in SUBSTITUTIONS:
                    # 70% chance to substitute instruction
                    if random.random() < 0.7:
                        try:
                            # Get operands
                            ops = instr.op_str.split(", ")
                            
                            # Select random substitution pattern
                            pattern = random.choice(SUBSTITUTIONS[instr.mnemonic])
                            
                            # Generate substituted instruction
                            if len(ops) == 2:
                                new_code = pattern(ops[0], ops[1])
                            else:
                                new_code = pattern(ops[0])
                            
                            # Assemble new instruction sequence
                            encoded, _ = self.ks.asm(new_code)
                            if encoded:
                                modified_code.extend(bytes(encoded))
                                continue
                            
                        except (KsError, ValueError, IndexError) as e:
                            logger.debug(f"Failed to substitute instruction: {e}")
                            modified_code.extend(instr.bytes)
                            continue
                
                # If no substitution, keep original instruction
                modified_code.extend(instr.bytes)
            
            return bytes(modified_code)
            
        except Exception as e:
            logger.error(f"Error in substitute_instructions: {e}")
            return original_code
        
    def flatten_control_flow(self, original_code: bytes) -> bytes:
        """Implement control flow flattening by splitting code into basic blocks with a dispatcher."""
        try:
            # Disassemble original code
            instructions = list(self.cs.disasm(original_code, 0))
            if not instructions:
                return original_code

            # Main flattening process
            blocks = identify_basic_blocks(instructions)
            flattened_asm = generate_flattened_code(blocks)
            
            # Assemble flattened code
            try:
                encoded, _ = self.ks.asm(flattened_asm)
                if encoded:
                    return bytes(encoded)
            except KsError as e:
                logger.error(f"Failed to assemble flattened code: {e}")
                return original_code

        except Exception as e:
            logger.error(f"Error in control flow flattening: {e}")
            return original_code 