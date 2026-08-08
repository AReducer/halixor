# Project Structure & Third-Party Management

## Repository layout

```
halixor/
├── halixor.java                 # HALIXOR analysis script (Ghidra)
├── config/analysis.config.json  # targets + DR channels + output settings
├── patch/qtre-local-changes.patch
├── dist/                        # self-contained runnable bundle
│   ├── halixor.java
│   ├── InitRam.java             # zero-initialized RAM pre-script
│   ├── ParamId.java             # parameter-prototype recovery post-script
│   ├── config/analysis.config.json
│   ├── benchmarks/              # stripped .bin samples (flat)
│   ├── src/                     # library sources (QtRE fork + vendored deps)
│   ├── run-headless.sh
│   ├── LICENSE / NOTICE
│   └── README.md
├── LICENSE
├── NOTICE
└── README.md
```

The library sources under `dist/src/` are a QtRE fork (Apache-2.0) with
analysis-specific extensions, plus the vendored `org/json` (Public Domain) and
`javafx.util.Pair` (OpenJFX, GPL-2.0 + Classpath exception).

## Recommended submodule setup

Ghidra and QtRE are externally versioned third-party trees; keep them out of
the repository history and track them as git submodules:

```
.gitmodules
    [submodule "ghidra"]
        path = ghidra
        url = https://github.com/NationalSecurityAgency/ghidra
        branch = 11.2.1
    [submodule "qtre"]
        path = qtre
        url = https://github.com/OSUSecLab/QtRE.git
```

1. **Ghidra** — reference the official `NationalSecurityAgency/ghidra` tag
   `Ghidra_11.2.1_build`. Note that the *binary distribution* is what runs;
   either vendor the release zip separately or clone the source tag.
2. **QtRE** — keep `OSUSecLab/QtRE` as a submodule and apply
   `patch/qtre-local-changes.patch` on top (or maintain a fork branch). The
   patch is the exact diff between upstream QtRE and the bundled `dist/src/`.
3. **Vendored libraries** — `org/json` can be replaced by the normal Maven
   dependency `org.json:json:20200518` (already used by QtRE's `pom.xml`).
   `javafx.util.Pair` can be replaced by `java.util.AbstractMap.SimpleEntry`
   to drop the OpenJFX dependency.
4. **Benchmarks** — firmware images are test data from external research
   projects (P2IM, HALucinator, uEmu, hal-fuzz, AWS FreeRTOS); keep them in
   Git LFS or fetch them from their upstream sources.

## Development workflow

```bash
git submodule update --init --recursive
# after changing dist/src/, regenerate the QtRE patch:
diff -ruN --exclude='._*' qtre/src dist/src > patch/qtre-local-changes.patch
```

`git diff` over the QtRE fork then shows only the analysis-specific changes.
