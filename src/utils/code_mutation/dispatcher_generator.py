#!/usr/bin/env python3

import random
from typing import List
from loguru import logger
from .block_analysis import BasicBlock

def generate_flattened_code(blocks: List[BasicBlock]) -> str:
    """
    Generate flattened assembly code with a dispatcher.
    
    Args:
        blocks: List of basic blocks to flatten
        
    Returns:
        String containing the flattened assembly code
    """
    try:
        # Create randomized state table
        state_table = {}
        block_order = list(range(len(blocks)))
        random.shuffle(block_order)
        
        # Map original addresses to state numbers
        addr_to_state = {block.address: i for i, block in enumerate(blocks)}
        
        # Generate unique random keys for state encryption
        state_key = random.randint(0x10000000, 0xFFFFFFFF)
        state_mask = random.randint(0x10000000, 0xFFFFFFFF)
        
        # Generate dispatcher prologue
        dispatcher = [
            "push ebp",
            "mov ebp, esp",
            "push ebx",                    # Save registers
            "push esi",
            "push edi",
            "sub esp, 16",                 # Local variables
            f"mov dword [ebp-4], {state_key ^ (block_order[0] ^ state_mask)}",  # Initial encrypted state
            "jmp dispatcher_start",
            
            "dispatcher_start:",
            f"mov eax, dword [ebp-4]",    # Load encrypted state
            f"xor eax, {state_key}",      # Decrypt state
            f"xor eax, {state_mask}",
            "mov ebx, eax",               # Save state for later
            
            # Generate switch table with encrypted states
            "switch_table:"
        ]

        # Generate jump table
        for i, block in enumerate(blocks):
            dispatcher.extend([
                f"cmp ebx, {i}",
                f"je block_{i}"
            ])

        dispatcher.append("jmp code_end")  # Default case
        
        # Generate flattened blocks
        flattened_blocks = []
        for i, block in enumerate(blocks):
            block_code = [f"block_{i}:"]
            
            # Add original instructions except last branch
            for instr in block.instructions[:-1]:
                if not instr.mnemonic.startswith('j'):  # Skip jumps
                    block_code.append(f"{instr.mnemonic} {instr.op_str}")
            
            # Handle block transitions
            last_instr = block.instructions[-1]
            if block.is_return:
                block_code.extend([
                    "mov esp, ebp",
                    "pop edi",
                    "pop esi",
                    "pop ebx",
                    "pop ebp",
                    "ret"
                ])
            elif block.is_conditional:
                # For conditional jumps, we need to handle both paths
                true_state = addr_to_state[block.true_target]
                false_state = addr_to_state[block.false_target]
                
                # Generate conditional state transition
                block_code.extend([
                    f"{last_instr.mnemonic} true_path_{i}",
                    f"mov eax, {false_state ^ state_key ^ state_mask}",
                    "jmp state_update",
                    f"true_path_{i}:",
                    f"mov eax, {true_state ^ state_key ^ state_mask}"
                ])
            else:
                # Direct jump to next block
                next_state = addr_to_state[block.next_block] if block.next_block else (i + 1) % len(blocks)
                block_code.append(f"mov eax, {next_state ^ state_key ^ state_mask}")
            
            # Update state and return to dispatcher
            if not block.is_return:
                block_code.extend([
                    "state_update:",
                    "mov dword [ebp-4], eax",
                    "jmp dispatcher_start"
                ])
            
            flattened_blocks.extend(block_code)
        
        # Combine all code sections
        full_code = "\n".join(dispatcher + flattened_blocks + ["code_end:"])
        return full_code
        
    except Exception as e:
        logger.error(f"Error in generate_flattened_code: {e}")
        return "" 