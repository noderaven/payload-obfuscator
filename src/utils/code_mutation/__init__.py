from .mutator import CodeMutation
from .block_analysis import BasicBlock, identify_basic_blocks
from .dispatcher_generator import generate_flattened_code
from .junk_instructions import JUNK_GROUPS
from .instruction_substitutions import SUBSTITUTIONS

__all__ = [
    'CodeMutation',
    'BasicBlock',
    'identify_basic_blocks',
    'generate_flattened_code',
    'JUNK_GROUPS',
    'SUBSTITUTIONS'
] 