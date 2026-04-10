# {{PROJECT_NAME}}

PlayStation EXE reverse engineering project created with CodeMunch Pro.

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

- **Type**: PlayStation EXE
- **CPU**: R3000A (MIPS)
- **Base Address**: 0x80010000
- **Header Size**: 2048 bytes

## Memory Map

| Region | Address Range | Size | Type |
|--------|---------------|------|------|
| Kernel RAM | 0x00000000-0x0000FFFF | 64KB | RAM |
| User RAM | 0x00010000-0x001FFFFF | 2MB | RAM |
| Expanded RAM | 0x00200000-0x007FFFFF | 6MB | RAM (with expansion) |
| BIOS ROM | 0x1FC00000-0x1FC7FFFF | 512KB | ROM |

## Getting Started

1. Place your PSX EXE file in the project directory
2. Import using: `codemunch-pro import --format psx-exe <exe_file>`
3. Start analyzing with the web interface: `codemunch-pro web`

## Recommended Tools

- [PCSX-Redux](https://github.com/grumpycoders/pcsx-redux) - PlayStation emulator with debugger
- [DuckStation](https://github.com/stenzek/duckstation) - PlayStation emulator
- [Ghidra](https://ghidra-sre.org/) - Reverse engineering framework with PSX loader
- [psx_rev](https://github.com/Vector35/psx_revs) - PSX Ghidra loader
