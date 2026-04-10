# {{PROJECT_NAME}}

Generic binary reverse engineering project created with CodeMunch Pro.

## Project Structure

```
{{PROJECT_NAME}}/
├── config.yml          # Project configuration
├── manifests/          # REX manifest files
│   └── example.json    # Example manifest
├── notes/              # Research notes
├── symbols/            # Symbol files
└── exports/            # Export output directory
```

## Platform Information

- **Type**: Generic Binary
- **Architecture**: Unknown (configure in config.yml)
- **Base Address**: 0x0

## Getting Started

1. Place your binary file in the project directory
2. Update `config.yml` with your target platform details
3. Import using: `codemunch-pro import --format bin <binary_file>`
4. Start analyzing with the web interface: `codemunch-pro web`

## Recommended Tools

- [Ghidra](https://ghidra-sre.org/) - Reverse engineering framework
- [Binary Ninja](https://binary.ninja/) - Binary analysis platform
- [IDA Pro](https://hex-rays.com/ida-pro/) - Interactive disassembler
