# Changelog
All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-02-28
### Added
- All features merged from development branch.
- Initial clean release for forked repository.

## [1.1.0] - 2026-03-08
### Added
- Added post-generation hook for agent file creation in `src_service/ts_agent_build.go`.
- Created forked Github repository for [AdaptixC2](https://github.com/MaorSabag/AdaptixC2) with code modifications to support StealthPalace.

## [1.1.1] - 2026-03-14
### Added
- Update Crystal Palace and specs files according to this [article](https://aff-wg.org/).
- Changed DLL execution via `DLLMAIN` function.

## [1.1.2] - 2026-03-15
### Added
- Added `install.sh` automated installer: builds COFF objects, patches the root path in `pl_agent.go`, marks Crystal Palace tools executable, builds the service extender plugin, and registers it in the Adaptix `profile.yaml` via `--ax <path>`.

### Changed
- Expanded README prerequisites into a full Installation section with an automated path (`install.sh`) and a manual step-by-step path.
- Added Crystal Palace toolchain prerequisites table covering all required packages (Java, MinGW, Clang/LLVM, Go).

## [1.2.0] - 2026-03-20
### Added
- **Sleep Obfuscation UI**: New collapsible "Sleep Obfuscation" group in the compile window lets you enable/disable Ekko at build time without touching source. The selected technique is persisted in settings and passed to the compiler as `-DSLEEP_OBF_EKKO`.
- **DLL Wrapping toggle**: Added "Enable DLL wrapping hook" checkbox to the compiler flags group; defaults to `true` and is saved/restored across sessions.
- **`.pdata` registration**: After reflective loading, the DLL's exception directory is registered with `RtlAddFunctionTable` so unwind info and SEH are fully functional in the beacon.
- New `RtlAddFunctionTable`, `RtlLookupFunctionEntry`, `GetModuleHandleA`, and `RtlCaptureContext` import stubs added to `loader.h`.
- Compiler flags `-fasynchronous-unwind-tables`, `-mabi=ms`, and `-foptimize-sibling-calls` are now always applied to produce correct unwind tables.
- **Stomp technique**: New options for stomping PICO and Agent's DLL
  - LoadLibraryEx (DONT_RESOLVE_DLL_REFERENCES) Loads the sacrificial DLL without resolving imports. Simple and reliable. However, the DLL is still subject to CFG and ETW callbacks, and a PEB loader entry is automatically created.
  - NtCreateSection + NtMapViewOfSection Maps the DLL directly via NT APIs, synthetic LDR_DATA_TABLE_ENTRY is manually inserted into InLoadOrderModuleList and InMemoryOrderModuleList so stack walkers resolve the DLL name correctly.

### Changed
- **Stack improvements when not sleeping**: All Ekko-specific logic (ROP helpers, `EkkoObf`, `DetourWaitForMultipleObjects`, `RndThreadId`) is now gated behind `#ifdef SLEEP_OBF_EKKO`. Hook functions (`_WaitForSingleObjectEx`, `_WaitForMultipleObjects`, `_ConnectNamedPipe`) pass through cleanly to the real API when sleep obfuscation is disabled, instead of erroring or calling undefined code.
- Ekko dispatch extracted into a dedicated `__attribute__((noinline))` helper (`_WaitForSingleObjectEx_Obf`) to keep the hot-path stack frame minimal and predictable regardless of sleep state.
- Hook functions marked `__attribute__((optimize("O2"), noinline))` for consistent, small stack frames.
- `FlushInstructionCache` is now called **before** `DLL_PROCESS_ATTACH` (previously it was called after, which could lead to stale I-cache on the entry point).
- `Settings` global in `pl_main.go` is now initialized via `defaultSaveSettings()` to guarantee sane defaults even before a config file is loaded.
- Stomp mode allocates a dedicated `RUNTIME_FUNCTION` buffer for pico module entries, passed through `PICO_ARGS`.
- Ekko-specific function resolution (`NtContinue`, `RtlCaptureContext`, `SystemFunction032`) is only performed at startup when `SLEEP_OBF_EKKO` is defined, avoiding unnecessary `LoadLibrary` calls otherwise.

## [1.3.0] - 2026-05-13
### Added
- **Control Flow Guard (CFG) gadget registration**: New `src/cfg.c` + `src/cfg.h` introduces `_cfg_mark_region`, `_cfg_mark_single`, `_cfg_mark_single_image`, `EnableCFG`, `EnableCFGForPICO`, and primitives built on top of `NtSetInformationVirtualMemory(VmCfgCallTargetInformation)`. Sleep-obfuscation ROP gadgets (Ekko and Kraken Mask) are now registered as valid CFG call targets so the loader survives on CFG-enabled hosts. Agent executable sections are re-marked after each VirtualProtect cycle inside the sleep hook.
- **Ekko refactored into standalone `src/ekko.c`** with an expanded 14-frame ROP chain (gate, VP_RW, encrypt, GetCtx, CopyRip, CopyTib, SetCtx, sleep, RestoreTib, SetCtxRestore, decrypt, restorePerms, setEvent) and thread-context / TIB swap so stack walkers see a spoof thread's stack range during sleep.
- **Kraken Mask sleep-obfuscation technique** (`src/kraken_mask.c`, selectable in the UI alongside Ekko). 16-context ROP, spoofed RSP sourced from a helper thread, full TIB swap, and RC4 image masking via `SystemFunction032`. Compiled with `-DSLEEP_OBF_KRAKEN_MASK`.
- **Phantom DLL Hollowing (NTFS transaction)** stomp technique. Selectable in the UI as a third option alongside `LoadLibraryEx` and `NtCreateSection + NtMapViewOfSection`. Compiled with `-DSTOMP_TECHNIQUE=2`.
- **XOR Encryption (optional)** UI group in the compile window. Wraps the final shellcode output with operator-supplied key XOR. Restricted to `Bin` format; validation enforces non-empty key. Adds `Xor` / `XorKey` to `Settings` and `Params`; new `applyXorEncryption()` post-build pass in `pl_agent.go`.
- **`WinMainCRTStartup` entry point** added to `loader/source/main/Exe.cc` so the linked EXE artifact runs without depending on the C runtime startup; `WinMain` now blocks via `WaitForSingleObject(INFINITE)` after `Runner()`.
- `#pragma once` guard added to `loader/include/Adaptix.h`.

### Changed
- **Build hardening**: Added `-falign-functions=1 -falign-jumps=1 -falign-loops=1` to both `Makefile` CFLAGS and `pl_agent.go` compile flags. Also adds `-Wno-multichar -Wno-unused-function -Wno-unused-variable -Wno-address` to suppress benign warnings during the COFF build.
- **GUI input validation**: Host DLL / Stomp DLL path fields now require a `.dll` suffix (case-insensitive) in addition to the existing non-empty check. New `endsWith(str, suffix)` helper added to `ax_config.axs`; error message clarified to "A Valid Host/Stomp DLL path is required when Stomp is enabled."
- **Crystal Palace specs**:
  - `loader.spec` and `pico.spec` now `load "../../build/cfg.x64.o"` and merge it.
  - `loader.spec` and `pico.spec` add `ised insert "CALL r/m64" $NOP +safe` to break the `defense_evasion_suspicious_call_stack_trailing_bytes` pattern by ensuring bytes after every indirect CALL site begin with `0x90`, not `0x4883`.
- **Crystal Palace toolchain binaries** (`coffparse`, `disassemble`, `link`, `piclink`) refreshed.
- `Makefile`: `cfg.x64.o` added to the `all:` target and build recipe.
- `pl_agent.go`: `cfg.c` added to the COFF compile list; new `case "phantom"` (stomp) and `case "kraken mask"` (sleep) dispatch arms.