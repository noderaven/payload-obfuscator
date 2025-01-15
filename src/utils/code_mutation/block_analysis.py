#!/usr/bin/env python3

from typing import List
from capstone import CsInsn
from loguru import logger

class BasicBlock:
    """Represents a basic block of instructions in the control flow graph."""
    
    def __init__(self, start_index: int, address: int):
        self.start_index = start_index
        self.address = address
        self.instructions: List[CsInsn] = []
        self.next_block = None
        self.is_conditional = False
        self.true_target = None
        self.false_target = None
        self.is_return = False

def identify_basic_blocks(instructions: List[CsInsn]) -> List[BasicBlock]:
    """
    Analyze instructions and split them into basic blocks.
    
    Args:
        instructions: List of disassembled instructions
        
    Returns:
        List of BasicBlock objects representing the control flow
    """
    try:
        blocks = []
        current_block = None
        branch_mnemonics = {
            'jmp': False, 'je': True, 'jne': True, 'jz': True, 
            'jnz': True, 'ja': True, 'jb': True, 'jae': True, 
            'jbe': True, 'call': False, 'ret': False
        }
        
        # First pass: Create blocks
        for i, instr in enumerate(instructions):
            # Start new block on branch or branch target
            if (current_block is None or 
                instr.mnemonic in branch_mnemonics or
                any(instr.address == int(target.op_str, 16) 
                    for block in blocks 
                    for target in block.instructions 
                    if target.mnemonic in branch_mnemonics and target.op_str)):
                
                if current_block:
                    blocks.append(current_block)
                current_block = BasicBlock(i, instr.address)
            
            current_block.instructions.append(instr)
            
            # Handle different types of control flow
            if instr.mnemonic in branch_mnemonics:
                current_block.is_conditional = branch_mnemonics[instr.mnemonic]
                if instr.mnemonic == 'ret':
                    current_block.is_return = True
                elif instr.op_str:  # Has a target
                    target_addr = int(instr.op_str, 16)
                    if current_block.is_conditional:
                        current_block.true_target = target_addr
                        # False target is next instruction
                        if i + 1 < len(instructions):
                            current_block.false_target = instructions[i + 1].address
                    else:
                        current_block.next_block = target_addr
        
        if current_block:
            blocks.append(current_block)
            
        return blocks
        
    except Exception as e:
        logger.error(f"Error in identify_basic_blocks: {e}")
        return [] 