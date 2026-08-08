// HALIXOR pre-script: create a zero-initialized RAM region.
//
// Stripped firmware images (.bin) carry no memory map. This script creates an
// initialized RAM block (filled with 0) so that the analysis can overwrite
// peripheral-handler globals without "write to uninitialized memory" errors.
//
// Usage (headless):
//   -preScript InitRam.java [base] [size]
//   default base = 0x20000000 (STM32 SRAM), default size = 0x20000 (128 KB)

//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class InitRam extends GhidraScript {

    @Override
    public void run() throws Exception {
        long base = 0x20000000L;
        long size = 0x20000L;

        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].trim().isEmpty()) {
            base = Long.decode(args[0].trim());
        }
        if (args != null && args.length > 1 && !args[1].trim().isEmpty()) {
            size = Long.decode(args[1].trim());
        }

        Memory mem = currentProgram.getMemory();
        Address baseAddr = toAddr(base);
        if (mem.getBlock(baseAddr) != null) {
            println("[InitRam] RAM block already exists at " + baseAddr + ", skipping");
            return;
        }

        MemoryBlock ram = mem.createInitializedBlock("ram", baseAddr, size, (byte) 0, monitor, false);
        println("[InitRam] created initialized RAM block: " + ram.getName()
                + " " + ram.getStart() + " - " + ram.getEnd());
    }
}
