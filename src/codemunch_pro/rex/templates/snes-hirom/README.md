# {{PROJECT_NAME}}

SNES HiROM reverse engineering project created with CodeMunch Pro.

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

- **Type**: SNES HiROM
- **CPU**: W65C816S (65c816)
- **Base Address**: 0xC00000
- **Header Address**: 0xFFC0

## Memory Map

| Region | Address Range | Size | Type |
|--------|---------------|------|------|
| System RAM | 0x7E0000-0x7FFFFF | 128KB | RAM |
| Expansion RAM | 0x400000-0x5FFFFF | 2MB | RAM |
| ROM Low | 0x808000-0xFFFFFF | 8MB | ROM (mirrored) |
| ROM High | 0xC00000-0xFFFFFF | 4MB | ROM |

## Getting Started

1. Place your ROM file in the project directory
2. Import using: `codemunch-pro import --format bin <rom_file>`
3. Start analyzing with the web interface: `codemunch-pro web`

## Recommended Tools

- [bsnes-plus](https://github.com/devinacker/bsnes-plus) - SNES emulator with debugger
- [Mesen-S](https://github.com/SourMesen/Mesen-S) - SNES emulator with debugging features
- [Ghidra](https://ghidra-sre.org/) - Reverse engineering framework
