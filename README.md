# veh-hwbp-tracer

Lightweight **Vectored Exception Handling (VEH)** and hardware debug register (`DR0`–`DR7`) instruction tracer for Windows binary crash triage and vulnerability reproduction.

## Overview

When diagnosing complex memory corruption bugs or tracing packed binaries in an isolated sandbox, software breakpoints (`0xCC` / `INT3`) can inadvertently modify code page hashes or corrupt self-modifying instruction streams. `veh-hwbp-tracer` provides a clean C++ wrapper around hardware debug registers (`DR0`–`DR3`) and Windows Vectored Exception Handling (`AddVectoredExceptionHandler`) to record execution hits and memory watchpoints non-intrusively.

## Core Capabilities

- **Thread-Aware Hardware Breakpoints:** Configures `DR0`–`DR3` linear addresses with programmable condition masks (Execute `0b00`, Write `0b01`, Read/Write `0b11`) and lengths (1, 2, 4, or 8 bytes).
- **Resume Flag (`EFLAGS.RF`) Management:** Automatically sets bit 16 (`0x10000`) in the exception `CONTEXT::EFlags` upon hitting an execution breakpoint so execution continues cleanly without re-triggering on the same instruction.
- **Structured Telemetry Callback:** Supplies instruction pointer (`RIP`), stack pointer (`RSP`), and general-purpose register snapshots to user-defined analysis callbacks.

## Usage Example

```cpp
#include "veh_tracer.hpp"
#include <cstdio>

int main() {
    veh_tracer::HardwareTracer tracer;
    tracer.initialize([](const veh_tracer::TraceRecord& rec) {
        std::printf("[HWBP Slot %u] RIP=0x%llx RSP=0x%llx\n",
                    rec.slot_index, rec.rip, rec.rsp);
    });

    // Install an execution watchpoint on target function
    tracer.set_breakpoint(0, reinterpret_cast<uintptr_t>(&target_routine),
                          veh_tracer::TriggerCondition::Execute,
                          veh_tracer::WatchLength::Byte1);
    return 0;
}
```

> **Note:** Research tooling component for defensive crash triage and dynamic binary analysis.

## License

MIT License

