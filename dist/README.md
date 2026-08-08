# HALIXOR Distribution

Self-contained package: the HALIXOR Ghidra script, the QtRE-derived library
sources, the vendored dependencies and the benchmark samples.

```
dist/
├── halixor.java                 # analysis script (runs on stripped .bin)
├── InitRam.java                 # pre-script: create a zero-initialized RAM block
├── ParamId.java                 # post-script: recover function parameter prototypes
├── config/analysis.config.json  # targets + DR channels + output dir
├── benchmarks/                  # stripped firmware images (flat .bin list)
├── src/                         # library sources (QtRE fork + org/json + javafx Pair)
├── run-headless.sh              # one-shot headless runner
├── LICENSE                      # Apache-2.0
└── NOTICE                       # third-party attribution
```

## Quick start

```bash
GHIDRA_HOME=/path/to/ghidra_11.2.1_PUBLIC ./run-headless.sh benchmarks/hal-uart.bin
```

The runner replicates the original workflow for each stripped image:

1. import the `.bin` as little-endian ARM Cortex-M3 (`ARM:LE:32:Cortex`) raw
   binary at flash base `0x08000000`;
2. `InitRam.java` creates a zero-initialized RAM block at `0x20000000`
   (default 128 KB) so writes to handler globals never hit uninitialized
   memory;
3. Ghidra's standard analysis runs;
4. `ParamId.java` recovers function parameter prototypes via the decompiler;
5. `halixor.java` performs the HAL API model extraction.

Results are written to `output/` next to this package (override with
`OUTPUT_DIR=...`); RAM base/size are configurable via `RAM_BASE` / `RAM_SIZE`.

For instructions on testing a new `.bin` (preparation, config entry,
verification and troubleshooting), see the
["Testing a new `.bin` file"](../README.md#testing-a-new-bin-file) section of
the top-level README.

## Benchmarks

| Sample | Peripherals (DR) |
|--------|------------------|
| `benchmarks/st-plc.bin` | SPI `0x4001300c`, USART1 `0x40004404`, USART2 `0x40011004` |
| `benchmarks/hal-uart.bin` | UART `0x40011004` |
| `benchmarks/Robot.bin` | I2C `0x40005410` |
| `benchmarks/Drone.bin` | I2C `0x40005410`, USART `0x40013804` |
| `benchmarks/Soldering_Iron.bin` | I2C `0x40005410` |
| `benchmarks/uEmu.LiteOS_IoT.bin` | UART `0x40004424` |
| `benchmarks/jobs.bin` | SPI `0x40003c0c` |

## Outputs

For each run: `<program>.vlog` (run log), `<program>.out` (MMIO accesses),
`<program>.memout` (memory overwrites), `<program>.taintout` (taint findings)
and `<program>.json` (HAL API model). See the top-level
[`README.md`](../README.md) for the model format.
