// HALIXOR post-script: recover function parameter prototypes.
//
// Runs Ghidra's decompiler-based parameter identification over the whole
// program after the standard analysis has created functions. This mirrors the
// "Decompiler Parameter ID" step of the original workflow and is required by
// halixor.java to enumerate the buffer parameters of HAL APIs.
//
// Usage (headless, before halixor.java):
//   -postScript ParamId.java -postScript halixor.java <config>

//@category Analysis

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class ParamId extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("[ParamId] running decompiler parameter ID over all functions...");
        DecompilerParameterIdCmd cmd = new DecompilerParameterIdCmd(
                "HALIXOR parameter ID",
                currentProgram.getMemory().getExecuteSet(),
                SourceType.ANALYSIS,
                true,   // commit data types
                true,   // commit void returns
                60);    // decompiler timeout (s)
        cmd.applyTo(currentProgram, monitor);
        println("[ParamId] done");
    }
}
