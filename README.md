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
python -m venv venv
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

### Section Name Randomization

```python
from payload_obfuscator.src.obfuscator import PayloadObfuscator

obfuscator = PayloadObfuscator("input.exe", "output_dir")
pe = obfuscator.pe_handler.load_pe("input.exe")

# Randomize specific section
section = pe.sections[0]
obfuscator.section_handler.randomize_section_name(pe, section, strategy="random")

# Randomize all non-critical sections
obfuscator.section_handler.randomize_all_section_names(pe, skip_critical=True, strategy="mimic")
```

### Section Splitting

```python
# Split a large section into smaller ones
section = pe.sections[0]
split_sections = obfuscator.section_handler.split_section(pe, section, split_size=4096)
```

### Content Transformation

```python
# Apply encryption to a section
section = pe.sections[0]
obfuscator.section_handler.transform_section_content(pe, section, "encrypt")

# Apply polymorphic changes
snapshot = obfuscator.section_handler.apply_polymorphic_characteristics(pe, section)
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

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational purposes only, specifically for practicing techniques covered in the OSEP exam within authorized lab environments. The authors are not responsible for any misuse or damage caused by this tool.

## Acknowledgments

- OSEP (PEN-300) course material
- PE format documentation
- Python pefile library
