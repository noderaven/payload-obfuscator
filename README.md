# Payload Obfuscator

A Python-based tool for studying and practicing Windows PE binary obfuscation techniques in the context of the OSEP (PEN-300) exam preparation. This tool is designed for educational purposes and should only be used in authorized lab environments.

## Features

### PE Section Manipulation
- Section creation and modification
- Section splitting and merging
- Space validation and alignment
- Section table updates

### Section Name Obfuscation
- Random name generation
- Common section name mimicry
- Length-preserving mutations
- PE format compatibility validation

### String Obfuscation
- Multiple encryption algorithms (XOR, AES, RC4, custom)
- Dynamic key generation
- String detection and encryption
- Runtime decryption support
- Resource string manipulation
- String table modification

### Anti-Analysis Features
- Debugger detection and evasion
- Virtualization detection
- Process environment checks
- Hardware breakpoint detection
- API hooking detection
- Timing-based checks
- Parent process verification

### Content Transformation
- Section content encryption
- Base64 encoding
- Compression
- Polymorphic characteristics

### Safety Features
- Critical section protection
- PE format validation
- Alignment verification
- Comprehensive error handling

## Installation

```bash
# Clone the repository
git clone https://github.com/rileymxyz/payload_obfuscator.git
cd payload_obfuscator

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### As a Module

```python
from payload_obfuscator.src.obfuscator import PayloadObfuscator

# Initialize obfuscator
obfuscator = PayloadObfuscator("input.exe", "output_dir")

# Obfuscate the payload
obfuscator.obfuscate()
```

### From Command Line

```bash
python3 -m payload_obfuscator.src.obfuscator input.exe -o output_dir
```

## Advanced Usage Examples

### String Encryption

```python
from payload_obfuscator.src.obfuscator import PayloadObfuscator

obfuscator = PayloadObfuscator("input.exe", "output_dir")
pe = obfuscator.pe_handler.load_pe("input.exe")

# Encrypt strings using specific method
obfuscator.string_handler.encrypt_strings(pe, method="aes")

# Encrypt strings in specific sections
obfuscator.string_handler.encrypt_strings(pe, method="xor", section_names=[".text", ".data"])

# Get string table information
info = obfuscator.string_handler.get_string_table_info(pe)
```

### Anti-Analysis Features

```python
# Check execution environment
env_check = obfuscator.anti_analysis_handler.check_environment()

# Apply evasion techniques
obfuscator.anti_analysis_handler.apply_evasion_techniques(
    skip_debugger=False,
    skip_vm=False
)

# Get detailed environment info
env_info = obfuscator.anti_analysis_handler.get_environment_info()
```

### Section Name Randomization

```python
# Randomize specific section
section = pe.sections[0]
obfuscator.section_handler.randomize_section_name(pe, section, strategy="random")

# Randomize all non-critical sections
obfuscator.section_handler.randomize_all_section_names(pe, skip_critical=True, strategy="mimic")
```

## Security Considerations

1. This tool is for educational purposes only
2. Use only in authorized lab environments
3. Do not use on production systems
4. Follow all applicable laws and regulations
5. Practice responsible disclosure

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Disclaimer

This tool is intended for educational purposes only, specifically for practicing techniques within authorized lab environments. The authors are not responsible for any misuse or damage caused by this tool.

## Acknowledgments

- PE format documentation
- Python pefile library
