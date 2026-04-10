# {{PROJECT_NAME}}

Nintendo 64 ROM reverse engineering project created with CodeMunch Pro.

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

- **Type**: Nintendo 64 ROM
- **CPU**: VR4300 (MIPS64)
- **Base Address**: 0x80000000
- **Endianness**: Big Endian

## Memory Map

| Region | Address Range | Size | Type |
|--------|---------------|------|------|
| RDRAM | 0x80000000-0x803FFFFF | 4MB | RAM (8MB with Expansion Pak) |
| RDRAM (Uncached) | 0xA0000000-0xA03FFFFF | 4MB | RAM |
| Cartridge ROM | 0xB0000000-0xBFFFFFFF | 256MB | ROM |
| PIF ROM | 0x1FC00000-0x1FC007FF | 2KB | Boot ROM |

## Getting Started

1. Place your N64 ROM file in the project directory
2. Import using: `codemunch-pro import --format n64-rom <rom_file>`
3. Start analyzing with the web interface: `codemunch-pro web`

## Recommended Tools

- [Ares](https://ares-emu.net/) - N64 emulator with debugging
- [RMG](https://github.com/Rosalie241/RMG) - Rosalie's Mupen GUI
- [Ghidra](https://ghidra-sre.org/) - Reverse engineering framework with N64 loader
- [Splat](https://github.com/ethteck/splat) - N64 ROM splitting tool
- [decomp.me](https://decomp.me/) - MIPS decompilation playground
