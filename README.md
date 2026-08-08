# HALIXOR — Automated HAL API Model Extraction for Firmware Analysis

HALIXOR statically extracts **Hardware Abstraction Layer (HAL) API models** from
stripped ARM Cortex-M firmware binaries. Given a binary and the addresses of the
peripheral **data registers (DR)** of interest, HALIXOR:

1. repairs the Ghidra function database (IRQ handlers and uncovered branch
   targets);
2. resolves MMIO base objects (e.g. `hspi->Instance = 0x40003c00`) and
   overwrites them so constant propagation can follow peripheral-handler
   accesses;
3. discovers **MMIO driver functions (MDFs)** that load from / store to MMIO
   addresses;
4. runs PCode-level taint analysis to identify the buffer parameter of each
   HAL **receive** and **transmit** API (including interrupt-driven APIs whose
   buffers are filled by IRQ handlers);
5. emits a machine-readable HAL API model (JSON) consumable by firmware
   rehosting frameworks (e.g. the Fuzzware extension described in the paper).

> **Scope.** HALIXOR is designed for **stripped firmware binaries that are
> built on native vendor HAL libraries** (e.g. STM32Cube HAL) and communicate
> through on-chip **bus peripherals — SPI, I2C, UART, and similar** — whose
> data register (DR) addresses are known. The analysis relies on the standard
> HAL programming model: a peripheral handler object (e.g. `huart`) whose
> `Instance` field stores the peripheral MMIO base, and HAL APIs that pass a
> buffer parameter which either receives data from the DR (receive) or is
> written to the DR (transmit).

The approach is described in the accompanying paper
(*Automated HAL API Model Extraction for Firmware Analysis*, `halixor.pdf`).
The taint engine is built on
[QtRE](https://github.com/OSUSecLab/QtRE) (Apache-2.0).

---

## Repository layout

```
halixor/
├── halixor.java                 # analysis script (Ghidra)
├── config/analysis.config.json  # targets + DR channels + output settings
├── patch/qtre-local-changes.patch # local QtRE modifications (review diff)
├── dist/                        # self-contained runnable bundle
│   ├── halixor.java             # analysis script
│   ├── InitRam.java             # pre-script: create a zero-initialized RAM block
│   ├── ParamId.java             # post-script: recover function parameter prototypes
│   ├── config/analysis.config.json
│   ├── benchmarks/              # stripped firmware images (flat .bin list)
│   ├── src/                     # library sources (QtRE fork + vendored deps)
│   ├── run-headless.sh          # one-shot headless runner
│   ├── LICENSE / NOTICE
│   └── README.md
├── LICENSE                      # Apache-2.0
├── NOTICE                       # third-party attribution
└── README.md
```

The files at the repository root are the canonical copies; `dist/` is the same
content packaged for a self-contained release.

## Requirements

- Ghidra **11.2.1** and a JDK that Ghidra supports (11.2.1 requires Java 21).
- The library sources under `dist/src/` (QtRE fork + `org/json` +
  `javafx.util.Pair`).

### Setup

Ghidra 11 compiles every `.java` file in a script directory together as one
OSGi source bundle. The bundle is self-contained: the analysis script and the
library sources simply live in the same script directory.

The bundled `dist/run-headless.sh` handles this automatically:

```bash
GHIDRA_HOME=/path/to/ghidra_11.2.1_PUBLIC ./dist/run-headless.sh \
  dist/benchmarks/hal-uart.bin
```

For GUI use, copy `dist/halixor.java` **and** the `dist/src/` tree into one
Ghidra script directory.

## Configuration

All target-specific values live in
[`config/analysis.config.json`](config/analysis.config.json). 

```jsonc
{
  "schema_version": "1.0",
  "analysis": {
    "output_dir": "output",                 // where .out/.memout/.taintout/.json go
    "mmio_min": "0x40000000",               // peripheral address range
    "mmio_max": "0x60000000",
    "mmio_base_mask": "0xFFFFFF00"          // peripheral base-alignment mask
  },
  "targets": [
    {
      "program": "st-plc.bin",              // must match the Ghidra program name
      "description": "ST-PLC (hal-fuzz benchmark)",
      "language": "ARM:LE:32:Cortex",
      "data_registers": [                   // DR channels to analyze
        { "address": "0x4001300c", "peripheral": "SPI" },
        { "address": "0x40004404", "peripheral": "USART1" },
        { "address": "0x40011004", "peripheral": "USART2" }
      ]
    }
    // ... one entry per firmware image
  ]
}
```

`data_registers` lists the DR addresses of the on-chip communication
peripherals of interest (UART / SPI / I2C). Only MMIO accesses to these
registers are considered "DR" accesses by the taint analysis; all other MMIO
accesses are still logged but do not produce models. If no target matches the
loaded program, HALIXOR logs a warning and runs with DR filtering disabled.

Configuration resolution order:

1. first script argument (headless: `-postScript halixor.java <path>`);
2. system property `-Dhalixor.config=<path>`;
3. environment variable `HALIXOR_CONFIG=<path>`;
4. `<script directory>/config/analysis.config.json`.

## Usage

### GUI (Script Manager)

1. Open the target firmware in Ghidra (import as raw binary, language
   `ARM:LE:32:Cortex`).
2. If the program has no RAM map (stripped `.bin`), add a zero-initialized RAM
   block at `0x20000000` (e.g. run `InitRam.java`).
3. Run Ghidra's analysis, then run `ParamId.java` to recover parameter
   prototypes (required for buffer-parameter detection).
4. Run `halixor.java`.
5. Results are written to the configured `output_dir` as
   `<program name>.*` files.

### Headless (recommended for batch analysis)

The stripped `.bin` samples are imported as little-endian ARM Cortex-M3
(`ARM:LE:32:Cortex`), a zero-initialized RAM block is created, the standard
analysis runs, parameter prototypes are recovered, and then `halixor.java`
executes:

```bash
analyzeHeadless /path/to/project HALIXOR \
  -import dist/benchmarks/hal-uart.bin \
  -loader BinaryLoader -loader-baseAddr 0x08000000 \
  -processor ARM:LE:32:Cortex \
  -scriptPath dist \
  -preScript InitRam.java 0x20000000 0x20000 \
  -postScript ParamId.java \
  -postScript halixor.java /abs/path/to/config/analysis.config.json
```

Or simply use the wrapper:

```bash
GHIDRA_HOME=/path/to/ghidra_11.2.1_PUBLIC ./dist/run-headless.sh dist/benchmarks/hal-uart.bin
```

## Outputs

| File                  | Content                                                        |
|-----------------------|----------------------------------------------------------------|
| `<name>.vlog`         | full run log (all `println` output, timing)                    |
| `<name>.out`          | MMIO access log: `function pc mmio r|w`                        |
| `<name>.memout`       | memory writes recorded during constant propagation             |
| `<name>.taintout`     | taint findings (direct / indirect receive and transmit)        |
| `<name>.json`         | generated HAL API model                                        |

### Model format

```json
{
  "receive": [
    {
      "name": "HAL_UART_Receive_IT",
      "address": "8036d54",
      "buffer": 1,
      "size": 2,
      "hasReturn": true,
      "mmio": "40004404"
    }
  ],
  "transmit": [ /* same schema, transmit-direction APIs */ ],
  "not_modeled": [ "8035f08", "8036164" ]
}
```

- `receive` — receive-direction HAL APIs (DR → buffer): `buffer` is the
  1-based parameter index of the destination buffer; `size` is the first
  non-pointer parameter after it (or `-1`); `mmio` is the DR address that
  taints the buffer.
- `transmit` — transmit-direction HAL APIs (buffer → DR).
- `not_modeled` — driver functions that access MMIO but were not modeled.

## Testing a new `.bin` file

### 1. Prepare the input

- Use a **stripped** firmware image (`.bin`) built with a native HAL library.
  If you only have an ELF, extract the raw image first, e.g.:

  ```bash
  arm-none-eabi-objcopy -O binary --only-section=.isr_vector --only-section=.text \
    --only-section=.rodata --only-section=.data firmware.elf firmware.bin
  ```

- Note the MCU: flash base (usually `0x08000000` for STM32), RAM base and size
  (usually `0x20000000`, ≥ 128 KB), and which peripherals the firmware uses.

### 2. Configure the target

Add one entry to `config/analysis.config.json` per firmware image. The
`program` field must match the file name Ghidra will use (i.e. the `.bin` file
name), and `data_registers` lists the DR channels to analyze:

```jsonc
{
  "program": "my-fw.bin",
  "description": "my new firmware",
  "language": "ARM:LE:32:Cortex",
  "data_registers": [
    { "address": "0x40004404", "peripheral": "USART1" },
    { "address": "0x40005410", "peripheral": "I2C1" }
  ]
}
```

DR addresses for STM32 (from the reference manual, offset 0x04 of the
peripheral base): UART/USART DR, SPI DR, I2C DR, etc.

### 3. Run

```bash
GHIDRA_HOME=/path/to/ghidra_11.2.1_PUBLIC ./dist/run-headless.sh \
  dist/benchmarks/my-fw.bin
```

If the MCU's RAM is not at `0x20000000` or needs a different size:

```bash
RAM_BASE=0x20000000 RAM_SIZE=0x30000 ./dist/run-headless.sh my-fw.bin
```

The pipeline is: raw import at flash base → `InitRam` (zeroed RAM) → standard
analysis → `ParamId` (parameter prototypes) → `halixor.java`.

### 4. Verify the result

- `my-fw.bin.json` should contain `receive` / `transmit` entries:

  ```json
  {
    "receive": [ { "name": "FUN_08001384", "address": "8001384",
                   "buffer": 1, "size": 2, "hasReturn": true,
                   "mmio": "40011004" } ],
    "transmit": [ ],
    "not_modeled": [ "8000a20" ]
  }
  ```

- Cross-check with `my-fw.bin.taintout` (taint evidence) and the run log
  `my-fw.bin.vlog` (look for `check value at ... -> <mmio base>` overwrites).

### 5. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| empty `receive` / `transmit` | the DR addresses in the config don't match this firmware; check `my-fw.bin.out` for the MMIO addresses it actually accesses and verify against the datasheet (e.g. wrong USARTx) |
| no `Parameter i is a pointer` lines in the log | parameter prototypes were not recovered; make sure `ParamId.java` ran after analysis |
| no `check value at` overwrite in the log | the handler global was not found; check `RAM_BASE`/`RAM_SIZE` and that the firmware really stores the MMIO base into RAM (HAL-style) |
| script reports "no analysis target configured" | the program name doesn't match `targets[].program` (Ghidra names the program after the `.bin` file name) |
| functions not recovered | re-run with more Ghidra analysis (e.g. aggressive instruction finding) before `ParamId` |

No code changes are needed to analyze a new firmware — only the config entry.

## Ownership & attribution

- **HALIXOR tooling** — the analysis scripts, configuration, documentation and
  generated assets in this repository (`halixor.java`, `InitRam.java`,
  `ParamId.java`, `dist/`, `config/`, `patch/`) are maintained by the HALIXOR
  authors.
- **Benchmark firmware images** — the `.bin` files under `dist/benchmarks/` are
  **not our code**. They are test images from third-party research projects,
  bundled here for evaluation and reproduction only. Please consult the
  upstream projects for their licensing terms before redistribution:

  | Sample | Upstream project |
  |--------|------------------|
  | `st-plc.bin` | hal-fuzz (UCSB SecLab) — https://github.com/ucsb-seclab/hal-fuzz |
  | `hal-uart.bin` | HALucinator — https://github.com/embedded-sec/halucinator |
  | `Robot.bin`, `Drone.bin`, `Soldering_Iron.bin` | P2IM — https://github.com/RiS3-Lab/p2im |
  | `uEmu.LiteOS_IoT.bin` | uEmu (Zhou et al., USENIX Security 2021, "Automatic firmware emulation through invalidity-guided knowledge inference") |
  | `jobs.bin` | AWS FreeRTOS — https://github.com/aws/amazon-freertos |

## Third-party components & licenses

- **QtRE** (taint engine): Apache-2.0 —
  https://github.com/OSUSecLab/QtRE. Cite the USENIX Security 2023 paper
  *Egg Hunt in Tesla Infotainment* (Wen & Lin). Local modifications are
  tracked in [patch/qtre-local-changes.patch](patch/qtre-local-changes.patch).
- **Ghidra**: Apache-2.0 — https://ghidra-sre.org.
- **org/json** (JSON-java): Public Domain — https://github.com/stleary/JSON-java.
- **javafx.util.Pair**: derived from OpenJFX (GPL-2.0 with Classpath
  exception).

This repository is distributed under the **Apache License 2.0** — see
[LICENSE](LICENSE) and [NOTICE](NOTICE). See
[PROJECT-STRUCTURE.md](PROJECT-STRUCTURE.md) for the recommended submodule
based project layout.
