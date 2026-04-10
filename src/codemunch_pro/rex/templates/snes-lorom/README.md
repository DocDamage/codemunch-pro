# {{PROJECT_NAME}}

SNES LoROM reverse engineering project created with CodeMunch Pro.

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

- **Type**: SNES LoROM
- **CPU**: W65C816S (65c816)
- **Base Address**: 0x8000
- **Header Address**: 0x7FC0

## Memory Map

| Region | Address Range | Size | Type |
|--------|---------------|------|------|
| System RAM | 0x7E0000-0x7FFFFF | 128KB | RAM |
| Expansion RAM | 0x400000-0x5FFFFF | 2MB | RAM |
| ROM Banks | 0x008000-0x7FFFFF | 8MB | ROM (32KB banks) |

## Getting Started

1. Place your ROM file in the project directory
2. Import using: `codemunch-pro import --format bin <rom_file>`
3. Start analyzing with the web interface: `codemunch-pro web`

## Recommended Tools

- [bsnes-plus](https://github.com/devinacker/bsnes-plus) - SNES emulator with debugger
- [Mesen-S](https://github.com/SourMesen/Mesen-S) - SNES emulator with debugging features
- [Ghidra](https://ghidra-sre.org/) - Reverse engineering framework
