// HALIXOR: automated HAL API model extraction for firmware analysis
//
// This Ghidra script statically analyzes a stripped ARM Cortex-M firmware
// binary to:
//   1. repair the function database (IRQ handlers, uncovered branch targets);
//   2. locate MMIO base-address objects and overwrite them so that symbolic
//      constant propagation can resolve MMIO accesses;
//   3. discover "MMIO driver functions" (MDFs) that load from / store to
//      peripheral registers;
//   4. use PCode-level taint analysis (based on the QtRE taint engine) to
//      identify the buffer parameter of each HAL receive / transmit API;
//   5. emit a HAL API model (JSON) that can be consumed by firmware rehosting
//      frameworks such as Fuzzware.
//
// All target-specific values (firmware name, peripheral data-register / DR
// addresses, MMIO bounds, output directory) are read from a JSON configuration
// file, see config/analysis.config.json.
//
// Configuration resolution order:
//   1. first script argument   (headless: -postScript halixor.java <path>)
//   2. system property         -Dhalixor.config=<path>
//   3. environment variable    HALIXOR_CONFIG=<path>
//   4. default                 <script dir>/config/analysis.config.json

//@author
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.framework.store.LockException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeTranslator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import javafx.util.Pair;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import Taint.QTaintEngine;
import Main.Decompiler;

/**
 * HALIXOR static analysis script.
 *
 * <p>The analysis follows the pipeline described in the HALIXOR paper:
 * function repair, MMIO-base object resolution, MDF detection, PCode taint
 * analysis (receive / transmit) and HAL API model generation.</p>
 */
public class halixor extends GhidraScript {

    // ------------------------------------------------------------------
    //  Output writers
    // ------------------------------------------------------------------
    protected FileWriter writer;      // MMIO access log            (.out)
    protected FileWriter memWriter;   // memory write log           (.memout)
    protected FileWriter taintWriter; // taint findings             (.taintout)
    protected FileWriter logWriter;   // run log                    (.vlog)

    // ------------------------------------------------------------------
    //  Analysis state
    // ------------------------------------------------------------------
    // function entry -> (buffer parameter index, mmio)
    protected HashMap<Integer, Pair<Integer, Integer>> extractFuncModels = new HashMap<>();
    protected HashMap<Integer, Pair<Integer, Integer>> transmitFunctionModels = new HashMap<>();
    protected HashSet<Integer> conflictFuncs = new HashSet<>();

    // visited (hal, irq, param) tuples to keep recursive IRQ checks finite
    protected HashSet<String> exploredIrqSideEffectReceive = new HashSet<>();
    protected HashSet<String> exploredIrqSideEffectTransmit = new HashSet<>();
    protected HashSet<String> exploredBufferReceive = new HashSet<>();
    protected HashSet<String> exploredBufferTransmit = new HashSet<>();

    // per-target DR (data register) configuration
    protected HashSet<Integer> targetDRs = new HashSet<>();
    protected HashSet<Integer> relatedDRBases = new HashSet<>();

    protected Function currentAnalyzedFunction = null;
    protected VarnodeTranslator varTrans = null;

    // callback location -> [(writer function, callback entry), ...]
    protected HashMap<Address, ArrayList<Pair<Integer, Integer>>> callBackFuncMap = new HashMap<>();
    // driver function -> {(instruction pc, mmio address), ...}
    protected HashMap<Function, HashSet<Pair<Integer, Integer>>> drvFunctions = new HashMap<>();

    // IRQ number <-> handler entry
    protected HashMap<Integer, Integer> intMap = new HashMap<>();

    // global object address <-> mmio base value
    protected HashMap<Integer, Integer> mmioBaseStoreMap = new HashMap<>();

    protected AnalysisConfig config;
    protected AnalysisConfig.Target target;

    // ------------------------------------------------------------------
    //  Configuration
    // ------------------------------------------------------------------

    protected static class AnalysisConfig {
        String source;
        String outputDir = "output";
        long mmioMin = 0x40000000L;
        long mmioMax = 0x60000000L;
        long mmioBaseMask = 0xFFFFFF00L;
        Map<String, Target> targets = new LinkedHashMap<>();

        static class Target {
            String program = "";
            String description = "";
            String language = "ARM:LE:32:Cortex";
            LinkedHashMap<Integer, String> dataRegisters = new LinkedHashMap<>();
        }

        static AnalysisConfig load(GhidraScript script) throws Exception {
            String path = null;
            if (script.getScriptArgs() != null && script.getScriptArgs().length > 0) {
                path = script.getScriptArgs()[0];
            }
            if (path == null) {
                path = System.getProperty("halixor.config");
            }
            if (path == null) {
                path = System.getenv("HALIXOR_CONFIG");
            }
            if (path == null) {
                String srcPath = script.getSourceFile() == null ? null : script.getSourceFile().toString();
                if (srcPath != null) {
                    File srcFile = new File(srcPath);
                    if (srcFile.getParentFile() != null) {
                        path = new File(srcFile.getParentFile(), "config/analysis.config.json").getPath();
                    }
                } else {
                    path = "config/analysis.config.json";
                }
            }
            File file = new File(path);
            if (!file.isFile()) {
                throw new IOException("HALIXOR config file not found: " + file.getAbsolutePath());
            }
            AnalysisConfig cfg = parse(file);
            cfg.source = file.getAbsolutePath();
            return cfg;
        }

        static AnalysisConfig parse(File file) throws Exception {
            JSONObject root;
            try (InputStreamReader reader = new InputStreamReader(
                    new FileInputStream(file), StandardCharsets.UTF_8)) {
                root = new JSONObject(new JSONTokener(reader));
            }

            AnalysisConfig cfg = new AnalysisConfig();
            JSONObject analysis = root.optJSONObject("analysis");
            if (analysis != null) {
                cfg.outputDir = analysis.optString("output_dir", cfg.outputDir);
                cfg.mmioMin = parseHex(analysis.optString("mmio_min", "0x40000000"));
                cfg.mmioMax = parseHex(analysis.optString("mmio_max", "0x60000000"));
                cfg.mmioBaseMask = parseHex(analysis.optString("mmio_base_mask", "0xFFFFFF00"));
            }

            JSONArray targets = root.optJSONArray("targets");
            if (targets != null) {
                for (int i = 0; i < targets.length(); i++) {
                    JSONObject t = targets.getJSONObject(i);
                    Target target = new Target();
                    target.program = t.getString("program");
                    target.description = t.optString("description", "");
                    target.language = t.optString("language", target.language);
                    JSONArray drs = t.optJSONArray("data_registers");
                    if (drs != null) {
                        for (int j = 0; j < drs.length(); j++) {
                            JSONObject dr = drs.getJSONObject(j);
                            int addr = (int) parseHex(dr.getString("address"));
                            target.dataRegisters.put(addr, dr.optString("peripheral", ""));
                        }
                    }
                    cfg.targets.put(target.program, target);
                }
            }
            return cfg;
        }

        static long parseHex(String s) {
            String v = s.trim();
            if (v.startsWith("0x") || v.startsWith("0X")) {
                return Long.parseLong(v.substring(2), 16);
            }
            return Long.parseLong(v);
        }
    }

    /**
     * Resolve the target entry for the currently loaded program and pre-compute
     * the set of related MMIO bases used to filter IRQ handlers.
     */
    protected void initTarget() {
        String programName = currentProgram.getName();
        target = config.targets.get(programName);
        if (target == null) {
            String exePath = currentProgram.getExecutablePath();
            if (exePath != null) {
                target = config.targets.get(new File(exePath).getName());
            }
        }
        if (target == null) {
            println("[Warning] no analysis target configured for program '" + programName
                    + "'; DR filtering disabled (all MMIO accesses are still reported).");
            target = new AnalysisConfig.Target();
            return;
        }
        println("Loaded target '" + target.program + "'"
                + (target.description.isEmpty() ? "" : " (" + target.description + ")"));
        for (Integer dr : target.dataRegisters.keySet()) {
            targetDRs.add(dr);
            relatedDRBases.add(dr & (int) config.mmioBaseMask);
        }
        println("Configured DR registers: " + target.dataRegisters.keySet());
    }

    // ------------------------------------------------------------------
    //  Small predicates / helpers
    // ------------------------------------------------------------------

    protected boolean isMmio(long addr) {
        return addr >= config.mmioMin && addr <= config.mmioMax;
    }

    protected boolean isDR(Integer mmio) {
        return targetDRs.contains(mmio);
    }

    protected boolean isValidDR(Integer mmio, Integer mmioOld) {
        return isDR(mmio) && isDR(mmioOld);
    }

    protected static String hex(int v) {
        return Integer.toHexString(v);
    }

    @Override
    public void println(String str) {
        super.println(str);
        if (logWriter == null) {
            return;
        }
        try {
            logWriter.write(str + "\n");
            logWriter.flush();
        } catch (IOException e) {
            System.out.println("An error occurred in println: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------
    //  Symbolic propagation infrastructure (extended Ghidra analyzer)
    // ------------------------------------------------------------------

    /* inspired by https://github.com/NationalSecurityAgency/ghidra/issues/3581 */
    public class MemoryEnabledVarnodeContext extends VarnodeContext {

        protected ArrayList<Pair<Varnode, Varnode>> allMemAccesses = new ArrayList<>();

        public MemoryEnabledVarnodeContext(Program program, ProgramContext programContext,
                ProgramContext spaceProgramContext) {
            super(program, programContext, spaceProgramContext);
        }

        protected void recordCallBack(Varnode memnode, Varnode value) {
            if (!value.isConstant()) {
                return;
            }
            Integer val = (int) value.getOffset();
            if (!inCode(val)) {
                return;
            }
            if (!memnode.getAddress().getAddressSpace().getName().equals("ram")) {
                return;
            }
            Integer addr = (int) memnode.getOffset();
            if (!inRam(addr)) {
                return;
            }
            callBackFuncMap.computeIfAbsent(memnode.getAddress(), k -> new ArrayList<>())
                    .add(new Pair<>(currentAnalyzedFunction == null
                            ? 0x0
                            : (int) currentAnalyzedFunction.getEntryPoint().getOffset(), val));
        }

        @Override
        protected void putMemoryValue(Varnode out, Varnode value) {
            recordCallBack(out, value);
            try {
                String func = currentAnalyzedFunction == null
                        ? "None"
                        : Integer.toHexString((int) currentAnalyzedFunction.getEntryPoint().getOffset());
                memWriter.write(func + " " + out + " " + value + "\n");
                allMemAccesses.add(new Pair<>(out, value));
            } catch (IOException e) {
                System.out.println("[putMemoryValue] An error occurred: " + e.getMessage());
            }
            super.putMemoryValue(out, value);
        }

        public ArrayList<Pair<Varnode, Varnode>> getAllMemAccesses() {
            return allMemAccesses;
        }
    }

    public class EditableSymbolicPropagator extends SymbolicPropogator {

        public EditableSymbolicPropagator(Program program) {
            super(program);
            this.context = new MemoryEnabledVarnodeContext(program, this.programContext, this.spaceContext);
            this.context.setDebug(super.debug);
        }

        public ArrayList<Pair<Varnode, Varnode>> getAllMemAccesses() {
            return ((MemoryEnabledVarnodeContext) this.context).getAllMemAccesses();
        }

        public RegisterValue getRegisterValue(Register reg, Address addr) {
            return this.context.getRegisterValue(reg, addr);
        }

        public void setRegisterValue(RegisterValue value, Address addr) {
            this.context.setFutureRegisterValue(addr, value);
        }

        public Varnode getUniqueValue(Varnode vn, ContextEvaluator evaluator) {
            try {
                return this.context.getValue(vn, false, evaluator);
            } catch (Exception e) {
                return null;
            }
        }
    }

    class EditableConstantPropagationAnalyzer extends ConstantPropagationAnalyzer {
        protected ContextEvaluator eval;

        @Override
        public AddressSetView flowConstants(Program program, Address flowStart,
                AddressSetView flowSet, SymbolicPropogator symEval, TaskMonitor monitor)
                throws CancelledException {
            eval = new ConstantPropagationContextEvaluator(monitor)
                    .setTrustWritableMemory(trustWriteMemOption)
                    .setMinSpeculativeOffset(minSpeculativeRefAddress)
                    .setMaxSpeculativeOffset(maxSpeculativeRefAddress)
                    .setMinStoreLoadOffset(minStoreLoadRefAddress)
                    .setCreateComplexDataFromPointers(createComplexDataFromPointers);
            return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
        }

        public ContextEvaluator getEvaluator() {
            return eval;
        }
    }

    // ------------------------------------------------------------------
    //  HAL API model generation
    // ------------------------------------------------------------------

    class ModelGenerator {
        protected HashMap<Integer, Pair<Integer, Integer>> modeledFuncs;
        protected HashMap<Integer, Pair<Integer, Integer>> transmitModeledFuncs;
        protected HashSet<Integer> noModeledFuncs;

        public ModelGenerator(HashMap<Integer, Pair<Integer, Integer>> extractFuncModels,
                HashMap<Integer, Pair<Integer, Integer>> transmits, HashSet<Integer> conflictFuncs) {
            this.modeledFuncs = extractFuncModels;
            this.transmitModeledFuncs = transmits;
            this.noModeledFuncs = conflictFuncs;
        }

        public void generateFunctionModel(FileWriter writer) {
            JSONObject result = new JSONObject();
            result.put("receive", buildModels(modeledFuncs, "Generate Function Model"));
            result.put("transmit", buildModels(transmitModeledFuncs, "Generate Transmit Function Model"));
            result.put("not_modeled", buildNotModeled());
            try {
                writer.write(result.toString(4));
            } catch (IOException e) {
                System.out.println("[GenerateFunctionModel] An error occurred: " + e.getMessage());
            }
        }

        protected JSONArray buildModels(HashMap<Integer, Pair<Integer, Integer>> models, String logPrefix) {
            JSONArray out = new JSONArray();
            for (Integer fa : models.keySet()) {
                if (noModeledFuncs.contains(fa)) {
                    continue;
                }
                Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(fa));
                if (f == null) {
                    continue;
                }
                println(logPrefix + " for " + hex((int) f.getEntryPoint().getOffset()));
                Integer param = models.get(fa).getKey();
                Integer mmio = models.get(fa).getValue();
                DecompileResults decompileResults = Decompiler.decompileFunc(currentProgram, f);
                HighFunction highFunction = decompileResults.getHighFunction();
                ghidra.program.model.pcode.FunctionPrototype fp = highFunction.getFunctionPrototype();
                JSONObject funcModel = new JSONObject();
                funcModel.put("name", f.getName());
                funcModel.put("address", hex((int) f.getEntryPoint().getOffset()));
                funcModel.put("buffer", param);
                funcModel.put("size", findSizeArg(f, param));
                funcModel.put("hasReturn", !fp.hasNoReturn());
                funcModel.put("mmio", hex(mmio));
                out.put(funcModel);
            }
            return out;
        }

        protected JSONArray buildNotModeled() {
            JSONArray notModeled = new JSONArray();
            for (Function f : drvFunctions.keySet()) {
                Integer addr = (int) f.getEntryPoint().getOffset();
                if (modeledFuncs.containsKey(addr) || transmitModeledFuncs.containsKey(addr)) {
                    continue;
                }
                notModeled.put(hex(addr));
            }
            return notModeled;
        }

        protected Integer findSizeArg(Function f, Integer param) {
            int total = f.getParameterCount();
            // skip the tainted buffer parameter itself
            for (int i = param + 1; i < total; i++) {
                Parameter p = f.getParameter(i);
                if (!(p.getDataType() instanceof Pointer)) {
                    println("size arg is inferred to " + i);
                    return i;
                }
            }
            return -1;
        }
    }

    // ------------------------------------------------------------------
    //  MMIO-base memory rewriting
    // ------------------------------------------------------------------

    protected void overwriteMemory(Integer value, Integer addrToStore, Integer size, boolean isLittleEndian) {
        try {
            Memory mem = currentProgram.getMemory();
            Address target = toAddr(addrToStore);
            MemoryBlock block = mem.getBlock(target);
            if (block != null && !block.isInitialized()) {
                // .bss / heap globals are uninitialized in a clean import; convert
                // them to zero-initialized so the MMIO-base overwrite can proceed
                mem.convertToInitialized(block, (byte) 0);
            }
            mem.setInt(target, value, !isLittleEndian);
            println("check value at " + hex(addrToStore) + " -> "
                    + hex(mem.getInt(target, !isLittleEndian)));
        } catch (MemoryAccessException | LockException | NotFoundException e) {
            println(e.toString());
            println("failed to overwrite " + hex(addrToStore) + " with value " + hex(value));
        }
    }

    /**
     * Record the MMIO base stored at a RAM object. Overwrites the memory with the
     * concrete value once so that later symbolic propagation can resolve
     * accesses through the peripheral handler.
     *
     * @return true if the value was newly written, false if it was already recorded
     */
    protected boolean storeMmioBase(Integer addrToStore, Integer mmio) {
        if (mmioBaseStoreMap.containsKey(addrToStore)) {
            Integer storedValue = mmioBaseStoreMap.get(addrToStore);
            println("[Warning] already stored " + hex(storedValue) + " at " + hex(addrToStore));
            println("[Warning]\t-> same ? " + mmio.equals(storedValue));
            return false;
        }
        mmioBaseStoreMap.put(addrToStore, mmio);
        overwriteMemory(mmio, addrToStore, 4, true);
        return true;
    }

    protected ArrayList<Integer> binaryEdit(Function f, CodeUnit cu) {
        ArrayList<Integer> res = new ArrayList<>();
        EditableConstantPropagationAnalyzer analyzer = new EditableConstantPropagationAnalyzer();
        EditableSymbolicPropagator symEval = new EditableSymbolicPropagator(currentProgram);
        symEval.setParamRefCheck(false);
        symEval.setReturnRefCheck(false);
        symEval.setStoredRefCheck(false);
        try {
            analyzer.flowConstants(currentProgram, f.getEntryPoint(), f.getBody(), symEval, monitor);
        } catch (CancelledException e) {
            println("flowConstants CancelledException: " + e);
        }

        for (Pair<Varnode, Varnode> p : symEval.getAllMemAccesses()) {
            Varnode value = p.getValue();
            Varnode addr = p.getKey();
            if (!value.isConstant()) {
                continue;
            }
            Integer mmio = (int) value.getOffset();
            // e.g. (ram, 0x20001578, 4) (const, 0x40013800, 4)
            if (!isMmio(mmio) || (mmio & 0xFF) != 0) {
                continue;
            }
            if (!addr.getAddress().getAddressSpace().getName().equals("ram")) {
                continue;
            }
            Integer addrToStore = (int) addr.getOffset();
            if (inRam(addrToStore) && storeMmioBase(addrToStore, mmio)) {
                res.add(addrToStore);
            }
        }
        return res;
    }

    // ------------------------------------------------------------------
    //  Memory predicates
    // ------------------------------------------------------------------

    protected boolean inCode(Integer addr) {
        // generally code is in the first memory block
        return currentProgram.getMemory().getFirstRange().contains(toAddr(addr));
    }

    protected boolean inRam(Integer addr) {
        int i = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (i == 0) { // skip the first block (code)
                i++;
                continue;
            }
            if (block.isRead() && block.contains(toAddr(addr))) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    //  Constant-propagation driver discovery
    // ------------------------------------------------------------------

    protected void setArgsWithConstant(EditableSymbolicPropagator symEval, Instruction instr, Address callee) {
        for (Integer i = 0; i < 4; i++) {
            Register r = currentProgram.getRegister("r" + i);
            RegisterValue rv = symEval.getRegisterValue(r, instr.getMinAddress());
            symEval.setRegisterValue(rv, callee);
        }
    }

    protected boolean isBranchMnemonic(String mnemonic) {
        return mnemonic.equals("bl") || mnemonic.equals("blx")
                || mnemonic.equals("b") || mnemonic.equals("b.w") || mnemonic.equals("bx");
    }

    protected void runConstantPropagation(Function f, EditableSymbolicPropagator symEval) {
        EditableConstantPropagationAnalyzer analyzer = new EditableConstantPropagationAnalyzer();
        symEval.setParamRefCheck(true);
        symEval.setReturnRefCheck(true);
        symEval.setStoredRefCheck(true);
        currentAnalyzedFunction = f;
        try {
            analyzer.flowConstants(currentProgram, f.getEntryPoint(), f.getBody(), symEval, monitor);
        } catch (CancelledException e) {
            println("exception in flow constant of function " + hex((int) f.getEntryPoint().getOffset()));
            println("flowConstants CancelledException: " + e);
        }
    }

    /**
     * Resolve direct / indirect call targets at a branch instruction and invoke
     * the callback for each resolved callee after propagating concrete argument
     * registers into it.
     */
    protected void forEachCallee(Function f, Instruction instr, EditableSymbolicPropagator symEval,
            Consumer<Function> onCallee) {
        String defOpr = instr.getDefaultOperandRepresentation(0);
        if (defOpr.startsWith("r")) {
            Register reg = currentProgram.getRegister(defOpr);
            RegisterValue rv = symEval.getRegisterValue(reg, instr.getMinAddress());
            if (rv == null) {
                println("indirect call to " + defOpr + " but it is null");
                return;
            }
            Address callee = toAddr(rv.getUnsignedValue().intValue());
            println("indirect call to " + hex((int) callee.getOffset()) + " at "
                    + hex((int) instr.getMinAddress().getOffset()));
            setArgsWithConstant(symEval, instr, callee);
            onCallee.accept(currentProgram.getFunctionManager().getFunctionAt(callee));
        } else if (defOpr.startsWith("0x")) {
            Address callee = toAddr(Integer.parseInt(defOpr.substring(2), 16));
            if (inCode((int) callee.getOffset())
                    && currentProgram.getFunctionManager().getFunctionContaining(callee) != null
                    && !f.getBody().contains(callee)) {
                println("direct call to " + hex((int) callee.getOffset()) + " at "
                        + hex((int) instr.getMinAddress().getOffset()));
                setArgsWithConstant(symEval, instr, callee);
                onCallee.accept(currentProgram.getFunctionManager().getFunctionAt(callee));
            }
        }
    }

    /**
     * Find driver functions by running constant propagation from every function
     * that references a resolved MMIO base / handler object, following calls
     * transitively and recording LDR/STR accesses to MMIO.
     */
    protected void findDriverFunction(Function f, EditableSymbolicPropagator symEval, HashSet<Integer> traversed) {
        if (f == null) {
            return;
        }
        int entry = (int) f.getEntryPoint().getOffset();
        if (!traversed.add(entry)) {
            return;
        }

        EditableSymbolicPropagator se = (symEval != null)
                ? symEval
                : new EditableSymbolicPropagator(currentProgram);
        runConstantPropagation(f, se);

        for (Address addr : f.getBody().getAddresses(true)) {
            CodeUnit icu = currentProgram.getListing().getCodeUnitAt(addr);
            if (!(icu instanceof Instruction)) {
                continue;
            }
            Instruction instr = (Instruction) icu;
            String mnemonic = instr.getMnemonicString();

            if (mnemonic.startsWith("ldr")) {
                // TODO: support other addressing forms; currently only
                //       "ldr reg, [reg, #imm]"
                PcodeOp[] pcodeOps = instr.getPcode();
                if (pcodeOps.length != 2
                        || !pcodeOps[0].getMnemonic().equals("INT_ADD")
                        || !pcodeOps[1].getMnemonic().equals("LOAD")) {
                    continue;
                }
                PcodeOp addOp = pcodeOps[0];
                Varnode addEnd1 = addOp.getInput(0);
                Varnode addEnd2 = addOp.getInput(1);
                if (!addEnd1.isRegister() || !addEnd2.isConstant()) {
                    continue;
                }
                Register addreg = varTrans.getRegister(addEnd1);
                RegisterValue addrv = se.getRegisterValue(addreg, instr.getMinAddress());
                if (addrv == null) {
                    continue;
                }
                Integer addregValue = addrv.getUnsignedValue().intValue();
                Integer addrToLoadFrom = addregValue + (int) addEnd2.getOffset();
                if (isMmio(addrToLoadFrom)) {
                    try {
                        writer.write(" function " + hex(entry) + " "
                                + hex((int) instr.getAddress().getOffset()) + " "
                                + hex(addrToLoadFrom) + " r \n");
                    } catch (IOException e) {
                        System.out.println("An error occurred: " + e.getMessage());
                    }
                    drvFunctions.computeIfAbsent(f, k -> new HashSet<>())
                            .add(new Pair<>((int) instr.getAddress().getOffset(), addrToLoadFrom));
                }
            } else if (isBranchMnemonic(mnemonic)) {
                forEachCallee(f, instr, se, callee -> findDriverFunction(callee, se, traversed));
            } else if (mnemonic.startsWith("str")) {
                for (Reference ref : instr.getOperandReferences(1)) {
                    Integer mmio = (int) ref.getToAddress().getOffset();
                    if (isMmio(mmio)) {
                        try {
                            writer.write(" function " + hex(entry) + " "
                                    + hex((int) instr.getAddress().getOffset()) + " "
                                    + hex(mmio) + " w \n");
                        } catch (IOException e) {
                            System.out.println("An error occurred: " + e.getMessage());
                        }
                        drvFunctions.computeIfAbsent(f, k -> new HashSet<>())
                                .add(new Pair<>((int) instr.getAddress().getOffset(), mmio));
                    }
                }
            }
        }
    }

    /**
     * Recursively collect all MMIO addresses accessed by a function (through
     * direct references and transitively through calls).
     */
    protected void searchMMIOAccessrecursive(Function f, HashSet<Integer> accessedMMIOs,
            EditableSymbolicPropagator symEval, HashSet<Integer> traversed) {
        if (f == null) {
            return;
        }
        if (!traversed.add((int) f.getEntryPoint().getOffset())) {
            return;
        }

        EditableSymbolicPropagator se = (symEval != null)
                ? symEval
                : new EditableSymbolicPropagator(currentProgram);
        runConstantPropagation(f, se);

        for (Address addr : f.getBody().getAddresses(true)) {
            CodeUnit icu = currentProgram.getListing().getCodeUnitAt(addr);
            if (!(icu instanceof Instruction)) {
                continue;
            }
            Instruction instr = (Instruction) icu;
            String mnemonic = instr.getMnemonicString();
            if (mnemonic.startsWith("ldr") || mnemonic.startsWith("str")) {
                for (Reference r : instr.getOperandReferences(1)) {
                    Integer toInt = (int) r.getToAddress().getOffset();
                    if (isMmio(toInt)) {
                        accessedMMIOs.add(toInt);
                    }
                }
            } else if (isBranchMnemonic(mnemonic)) {
                forEachCallee(f, instr, se, callee -> searchMMIOAccessrecursive(callee, accessedMMIOs, se, traversed));
            }
        }
    }

    // ------------------------------------------------------------------
    //  IRQ handler identification
    // ------------------------------------------------------------------

    protected void identifyIrqHandlerAndInt() {
        Memory mem = currentProgram.getMemory();
        Address start = mem.getFirstRange().getMinAddress();
        for (int i = 0; i < 256; i++) {
            if (i == 0 || i == 1) { // skip initial sp and reset entry
                continue;
            }
            int handler;
            try {
                handler = mem.getInt(toAddr((int) start.getOffset() + i * 4), false);
            } catch (MemoryAccessException e) {
                println("MemoryAccessException at " + hex((int) start.getOffset() + i * 4));
                continue;
            }
            handler = handler & 0xFFFFFFFE;
            Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(handler));
            if (f != null) {
                println("handler " + hex(handler) + " is already a function");
                intMap.put(i, handler);
            } else if (inCode(handler)) {
                println("[Create] handler " + hex(handler) + " is not a function");
                createFunction(toAddr(handler), String.format("%08x", handler));
                intMap.put(i, handler);
            }
        }
    }

    protected Varnode getDestVarnode(Integer pc) {
        Instruction instr = getInstructionAt(toAddr(pc));
        if (instr == null) {
            println("[Warning] no instruction at " + hex(pc));
            return null;
        }
        if (instr.getMnemonicString().startsWith("ldr")) {
            Register r = instr.getRegister(0); // dest
            return varTrans.getVarnode(r);
        }
        println("[Warning] mmio ldr instruction");
        return null;
    }

    // ------------------------------------------------------------------
    //  Taint checks
    // ------------------------------------------------------------------

    /**
     * Unit check: is the argument varnode tainted by a value loaded from an
     * MMIO data register?
     */
    protected boolean checkTaint(Function hal, Varnode vn, Integer pc, Integer mmio) {
        println("taint mmio: " + hex(mmio));
        println("hal: " + hex((int) hal.getEntryPoint().getOffset()));
        println("vn: " + vn);
        QTaintEngine qt = new QTaintEngine(hal.getEntryPoint(), vn.toString(), currentProgram, this);
        qt.taintWithSingleReg();
        HashMap<Address, HashSet<Pair<PcodeOp, Varnode>>> taintMap = qt.getTaintEndpointsAtStore();

        Varnode dest = getDestVarnode(pc);
        if (dest == null) {
            println("[Warning]cannot get dest varnode of mmio ldr instruction");
            return false;
        }
        println(" pc: " + hex(pc) + " dest: " + dest);
        QTaintEngine qt2 = new QTaintEngine(toAddr(pc), dest.toString(), currentProgram, this);
        qt2.taintWithSingleReg();
        boolean ret = qt2.checkMMIOHitStoreEndpoint(taintMap);
        println("checkTaint: " + ret);
        return ret;
    }

    /**
     * Unit check: does the argument varnode contain data that is later written
     * to a configured DR register (transmit direction)?
     *
     * @return the DR address if the argument reaches a DR store, otherwise null
     */
    protected Integer checkTaintTransmit(Function hal, Varnode vn) {
        QTaintEngine qt = new QTaintEngine(hal.getEntryPoint(), vn.toString(), currentProgram, this);
        qt.taintWithSingleReg();
        HashSet<Pair<Integer, Integer>> accessMMIOs = drvFunctions.get(hal);
        if (accessMMIOs == null) {
            return null;
        }
        for (Pair<Integer, Integer> pair : accessMMIOs) {
            Integer pc = pair.getKey();
            Instruction i = getInstructionAt(toAddr(pc));
            if (i == null) {
                continue;
            }
            if (i.getMnemonicString().startsWith("str") && isDR(pair.getValue())) {
                if (qt.checkTransmitTaintAt(pc, pair.getValue())) {
                    return pair.getValue();
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    //  IRQ-handler side-effect analysis (receive + transmit)
    // ------------------------------------------------------------------

    /**
     * Check whether any of the IRQ handlers related to {@code hal} shares the
     * same MMIO base range (only DR-related bases are considered).
     */
    protected boolean functionAccessFromSameRange(Function f, HashSet<Integer> mmioBases) {
        HashSet<Integer> accessedMMIOs = new HashSet<>();
        searchMMIOAccessrecursive(f, accessedMMIOs, null, new HashSet<>());

        println("\t-> irq " + f.getName() + " accessed mmio: ");
        for (Integer mmio : accessedMMIOs) {
            println("\t->recursive find mmio: " + hex(mmio));
        }

        HashSet<Integer> accessedMMIOBases = new HashSet<>();
        for (Integer mmio : accessedMMIOs) {
            accessedMMIOBases.add(mmio & (int) config.mmioBaseMask);
        }
        if (!hitDRCollection(accessedMMIOBases)) {
            return false;
        }
        for (Integer mmioBase : accessedMMIOBases) {
            if (mmioBases.contains(mmioBase)) {
                return true;
            }
        }
        return false;
    }

    protected boolean hitDRCollection(HashSet<Integer> mmioBases) {
        for (Integer v : mmioBases) {
            if (relatedDRBases.contains(v)) {
                return true;
            }
        }
        return false;
    }

    protected HashSet<Function> findIrqHandler(Function hal) {
        HashSet<Pair<Integer, Integer>> mmioAPs = drvFunctions.get(hal);
        if (mmioAPs == null) {
            return null;
        }
        HashSet<Integer> allMmioBases = new HashSet<>();
        for (Pair<Integer, Integer> val : mmioAPs) {
            allMmioBases.add(val.getValue() & (int) config.mmioBaseMask);
        }
        for (Integer base : allMmioBases) {
            println("findIrqHandler mmio base: " + hex(base));
        }
        if (!hitDRCollection(allMmioBases)) {
            return new HashSet<>();
        }

        HashSet<Function> irqHandlers = new HashSet<>();
        for (Integer i : intMap.keySet()) {
            Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(intMap.get(i)));
            if (f != null && functionAccessFromSameRange(f, allMmioBases)) {
                irqHandlers.add(f);
            }
        }
        return irqHandlers;
    }

    /**
     * Scan an IRQ handler (and, recursively, its callees) for LDR instructions
     * that read from the given tainted buffer locations.
     */
    protected void collectIrqBufferTaints(Function hal, Function irq, int paramIndex,
            ArrayList<Integer> taintedBufferLocs, boolean transmit) {
        for (Address addr : irq.getBody().getAddresses(true)) {
            CodeUnit icu = currentProgram.getListing().getCodeUnitAt(addr);
            if (!(icu instanceof Instruction)) {
                continue;
            }
            Instruction instr = (Instruction) icu;
            String mnemonic = instr.getMnemonicString();
            if (mnemonic.startsWith("ldr")) {
                for (Reference r : instr.getOperandReferences(1)) {
                    for (int loc : taintedBufferLocs) {
                        if (r.getToAddress().getOffset() == loc) {
                            checkIrqBufferTaintAt(hal, irq, paramIndex, (int) instr.getMinAddress().getOffset(), transmit);
                        }
                    }
                }
            } else if (isBranchMnemonic(mnemonic)) {
                recurseIrqCallees(hal, irq, instr, paramIndex, taintedBufferLocs, transmit);
            }
        }
    }

    protected void recurseIrqCallees(Function hal, Function irq, Instruction instr, int paramIndex,
            ArrayList<Integer> taintedBufferLocs, boolean transmit) {
        String defOpr = instr.getDefaultOperandRepresentation(0);
        if (defOpr.startsWith("r")) {
            for (Reference r : instr.getOperandReferences(0)) {
                Address to = r.getToAddress();
                Function callee = currentProgram.getFunctionManager().getFunctionAt(to);
                if (callee != null && inCode((int) to.getOffset())) {
                    collectIrqBufferTaints(hal, callee, paramIndex, taintedBufferLocs, transmit);
                }
            }
        } else if (defOpr.startsWith("0x")) {
            Address callee = toAddr(Integer.parseInt(defOpr.substring(2), 16));
            Function calleeFunc = currentProgram.getFunctionManager().getFunctionAt(callee);
            if (calleeFunc != null && inCode((int) callee.getOffset()) && !irq.getBody().contains(callee)) {
                collectIrqBufferTaints(hal, calleeFunc, paramIndex, taintedBufferLocs, transmit);
            }
        }
    }

    /**
     * Check the IRQ side effect on HAL function parameter {@code paramIndex}:
     * the buffer pointer written by the HAL function is also read by a related
     * IRQ handler, which fills it from a DR register (receive) or writes it to
     * a DR register (transmit).
     */
    protected void checkIrqTainting(Function hal, Function irq, int paramIndex,
            ArrayList<Integer> taintedBufferLocs, boolean transmit) {
        if (hal.getEntryPoint().getOffset() == irq.getEntryPoint().getOffset()) {
            return;
        }
        String tuple = hex((int) hal.getEntryPoint().getOffset()) + " "
                + hex((int) irq.getEntryPoint().getOffset()) + " " + paramIndex;
        HashSet<String> explored = transmit ? exploredIrqSideEffectTransmit : exploredIrqSideEffectReceive;
        if (!explored.add(tuple)) {
            return;
        }
        collectIrqBufferTaints(hal, irq, paramIndex, taintedBufferLocs, transmit);
    }

    protected void checkIrqBufferTaintAt(Function hal, Function irq, int paramIndex, int loc, boolean transmit) {
        println("Buffer taint introduced at " + hex(loc));
        Varnode vn = getDestVarnode(loc);
        if (vn == null) {
            return;
        }
        QTaintEngine qt = new QTaintEngine(toAddr(loc), vn.toString(), currentProgram, this);
        qt.taintWithSingleReg();
        if (transmit) {
            checkIrqTransmitTaintAt(hal, irq, paramIndex, loc, qt);
        } else {
            checkIrqReceiveTaintAt(hal, irq, paramIndex, qt);
        }
    }

    protected void checkIrqReceiveTaintAt(Function hal, Function irq, int paramIndex, QTaintEngine qt) {
        HashMap<Address, HashSet<Pair<PcodeOp, Varnode>>> taintMap = qt.getTaintEndpointsAtStore();
        if (taintMap.isEmpty()) {
            return;
        }
        HashSet<Pair<Integer, Integer>> mmios = drvFunctions.get(irq);
        if (mmios == null) {
            return;
        }
        for (Pair<Integer, Integer> val : mmios) {
            Integer pc = val.getKey();
            Integer ldrMMIO = val.getValue();
            if (!isValidDR(ldrMMIO, ldrMMIO)) {
                // only seeking for mmio DR
                continue;
            }
            println("checking mmio cross taint " + hex(ldrMMIO) + " at " + hex(pc));
            Varnode dest = getDestVarnode(pc);
            if (dest == null) {
                println("[Warning]cannot get dest varnode of mmio ldr instruction");
                continue;
            }
            QTaintEngine qt2 = new QTaintEngine(toAddr(pc), dest.toString(), currentProgram, this);
            qt2.taintWithSingleReg();
            if (qt2.checkMMIOHitStoreEndpoint(taintMap)) {
                recordIrqReceiveTaint(hal, irq, paramIndex, ldrMMIO);
            }
        }
    }

    protected void recordIrqReceiveTaint(Function hal, Function irq, int paramIndex, Integer ldrMMIO) {
        try {
            taintWriter.write("IRQ " + irq + " Taint Function "
                    + hex((int) hal.getEntryPoint().getOffset()) + " parameter " + paramIndex
                    + " is tainted by mmio:" + hex(ldrMMIO) + "\n");
            taintWriter.flush();
            int entry = (int) hal.getEntryPoint().getOffset();
            if (extractFuncModels.containsKey(entry)) {
                Integer param = extractFuncModels.get(entry).getKey();
                Integer mmio = extractFuncModels.get(entry).getValue();
                if (!param.equals(paramIndex)) {
                    taintWriter.write("[Warning] function " + hex(entry)
                            + " has multiple taint buffer parameters\n");
                    taintWriter.flush();
                    conflictFuncs.add(entry);
                }
                if (!ldrMMIO.equals(mmio)) {
                    if (!isValidDR(ldrMMIO, mmio)) {
                        taintWriter.write("[Warning] function " + hex(entry)
                                + " has multiple mmio taint source\n");
                        taintWriter.flush();
                        conflictFuncs.add(entry);
                    }
                    extractFuncModels.put(entry, new Pair<>(paramIndex, ldrMMIO));
                }
            } else {
                extractFuncModels.put(entry, new Pair<>(paramIndex, ldrMMIO));
            }
        } catch (IOException e) {
            System.out.println("An error occurred in checkIrqTainting " + e.getMessage());
        }
    }

    protected void checkIrqTransmitTaintAt(Function hal, Function irq, int paramIndex, int loc, QTaintEngine qt) {
        Function thecontext = getFunctionContaining(toAddr(loc));
        if (thecontext == null) {
            return;
        }
        HashSet<Pair<Integer, Integer>> accessMMIOs = drvFunctions.get(thecontext);
        if (accessMMIOs == null) {
            return;
        }
        for (Pair<Integer, Integer> pair : accessMMIOs) {
            Integer pc = pair.getKey();
            Instruction inst = getInstructionAt(toAddr(pc));
            if (inst == null) {
                continue;
            }
            if (inst.getMnemonicString().startsWith("str") && isDR(pair.getValue())
                    && qt.checkTransmitTaintAt(pc, pair.getValue())) {
                try {
                    taintWriter.write("[Indirect] Function "
                            + hex((int) hal.getEntryPoint().getOffset()) + " parameter " + paramIndex
                            + " is tainted by DR w " + hex((int) irq.getEntryPoint().getOffset()) + "\n");
                    taintWriter.flush();
                    transmitFunctionModels.put((int) hal.getEntryPoint().getOffset(),
                            new Pair<>(paramIndex, pair.getValue()));
                } catch (IOException e) {
                    System.out.println("An error occurred in analyzeArgWithMMIOTaint W " + e.getMessage());
                }
            }
        }
    }

    /**
     * Check whether the argument {@code paramIndex} of {@code hal} has an IRQ
     * side effect. {@code transmit} selects the transmit (DR-write) analysis;
     * otherwise the receive (DR-read) analysis is performed.
     */
    protected void checkIrqSideEffect(Function hal, int paramIndex,
            ArrayList<Integer> taintedBufferLocs, boolean transmit) {
        StringBuilder sb = new StringBuilder();
        sb.append(hal.getName()).append('_').append(paramIndex).append('_');
        for (int loc : taintedBufferLocs) {
            sb.append(loc).append('_');
        }
        String key = sb.toString();
        HashSet<String> explored = transmit ? exploredBufferTransmit : exploredBufferReceive;
        if (!explored.add(key)) {
            return;
        }

        HashSet<Function> irqs = findIrqHandler(hal);
        println("Function " + hex((int) hal.getEntryPoint().getOffset()) + " has "
                + irqs.size() + " irq handlers");
        if (irqs.isEmpty()) {
            return;
        }
        for (Function irq : irqs) {
            println("checking irq: " + irq.getName() + " side effect on "
                    + hex((int) hal.getEntryPoint().getOffset()) + " parameter " + paramIndex);
            checkIrqTainting(hal, irq, paramIndex, taintedBufferLocs, transmit);
        }
    }

    // ------------------------------------------------------------------
    //  Buffer-parameter analysis
    // ------------------------------------------------------------------

    protected ArrayList<Integer> checkArgWriteToMem(Function hal, Varnode vn) {
        QTaintEngine qt = new QTaintEngine(hal.getEntryPoint(), vn.toString(), currentProgram, this);
        qt.taintWithSingleReg();
        ArrayList<Integer> res = new ArrayList<>();
        for (int loc : qt.checkBufferStoreToMem()) {
            if (inRam(loc)) { // buffer has been written to ram
                res.add(loc);
            }
        }
        return res;
    }

    protected boolean isLevelOnePointer(DataType dt) {
        if (dt instanceof Pointer) {
            return !(((Pointer) dt).getDataType() instanceof Pointer);
        }
        return false;
    }

    /**
     * Iterate over the buffer-like parameters (index &gt;= 1; parameter 0 is the
     * peripheral handler) of a HAL driver function.
     */
    protected void forEachBufferParameter(Function hal, BiConsumer<Integer, Varnode> consumer) {
        int total = hal.getParameterCount();
        for (int i = 1; i < total; i++) {
            Parameter p = hal.getParameter(i);
            Varnode[] vns = p.getVariableStorage().getVarnodes();
            if (vns.length != 1) {
                println("[Warning] parameter " + i + " has more than one varnode");
                continue;
            }
            consumer.accept(i, vns[0]);
        }
    }

    /**
     * Analyze a driver function for receive-type taint: an argument whose value
     * reaches a store that also receives data loaded from a DR register.
     */
    protected void analyzeArgWithMMIOTaint(Function hal, Integer pc, Integer mmio) {
        forEachBufferParameter(hal, (i, vn) -> {
            println(hal.getName() + " Parameter " + i + " is a pointer");
            if (!checkTaint(hal, vn, pc, mmio)) {
                // no direct taint: check whether the pointer is written to memory
                ArrayList<Integer> taintedBufferLocs = checkArgWriteToMem(hal, vn);
                if (!taintedBufferLocs.isEmpty()) {
                    println("Parameter " + i + " is written to memory");
                    checkIrqSideEffect(hal, i, taintedBufferLocs, false);
                }
            } else {
                analyzeDirectReceiveTaint(hal, i, mmio);
            }
        });
    }

    protected void analyzeDirectReceiveTaint(Function hal, int paramIndex, Integer mmio) {
        try {
            if (!isValidDR(mmio, mmio)) {
                taintWriter.write("[DIRECT TAINT BUT NOT DR]function "
                        + hex((int) hal.getEntryPoint().getOffset()) + "\n");
                taintWriter.flush();
                return;
            }
            // direct taint: make sure the tainted parameter is a level-1 pointer
            DataType dt = hal.getParameter(paramIndex).getDataType();
            if (!isLevelOnePointer(dt)) {
                taintWriter.write("[DIRECT TAINT BUT NOT POINTER] Function "
                        + hex((int) hal.getEntryPoint().getOffset()) + " parameter " + paramIndex
                        + " is tainted by mmio:" + hex(mmio) + "\n");
                return;
            }
            taintWriter.write("Function " + hex((int) hal.getEntryPoint().getOffset())
                    + " parameter " + paramIndex + " is tainted by mmio:" + hex(mmio) + "\n");
            taintWriter.flush();
            recordExtractModel(hal, paramIndex, mmio);
        } catch (IOException e) {
            System.out.println("An error occurred in analyzeArgWithMMIOTaint " + e.getMessage());
        }
    }

    protected void recordExtractModel(Function hal, int paramIndex, Integer mmio) {
        int entry = (int) hal.getEntryPoint().getOffset();
        if (extractFuncModels.containsKey(entry)) {
            Integer param = extractFuncModels.get(entry).getKey();
            Integer mmioOld = extractFuncModels.get(entry).getValue();
            if (!param.equals(paramIndex)) {
                try {
                    taintWriter.write("[Warning] function " + hex(entry)
                            + " has multiple taint buffer parameters\n");
                    taintWriter.flush();
                } catch (IOException e) {
                    System.out.println("An error occurred in analyzeArgWithMMIOTaint " + e.getMessage());
                }
                conflictFuncs.add(entry);
            }
            if (!mmio.equals(mmioOld)) {
                /*
                 * the same HAL function can handle different IRQ handlers; if the pc loads from
                 * multiple sources we still consider it a valid taint as long as both sources
                 * are configured DR registers.
                 */
                if (!isValidDR(mmio, mmioOld)) {
                    try {
                        taintWriter.write("[Warning] function " + hex(entry)
                                + " has multiple mmio taint source\n");
                        taintWriter.flush();
                    } catch (IOException e) {
                        System.out.println("An error occurred in analyzeArgWithMMIOTaint " + e.getMessage());
                    }
                    conflictFuncs.add(entry);
                } else {
                    extractFuncModels.put(entry, new Pair<>(paramIndex, mmio));
                }
            }
        } else {
            extractFuncModels.put(entry, new Pair<>(paramIndex, mmio));
        }
    }

    /**
     * Analyze a driver function for transmit-type taint: an argument whose data
     * is written to a configured DR register.
     */
    protected void analyzeTransmitFunc(Function hal) {
        forEachBufferParameter(hal, (i, vn) -> {
            Integer targetDR = checkTaintTransmit(hal, vn);
            if (targetDR == null) {
                ArrayList<Integer> taintedBufferLocs = checkArgWriteToMem(hal, vn);
                if (!taintedBufferLocs.isEmpty()) {
                    println("Parameter " + i + " is written to memory");
                    checkIrqSideEffect(hal, i, taintedBufferLocs, true);
                }
            } else {
                analyzeDirectTransmitTaint(hal, i, targetDR);
            }
        });
    }

    protected void analyzeDirectTransmitTaint(Function hal, int paramIndex, Integer targetDR) {
        try {
            println("checkTaintTransmit returns a value " + hex(targetDR));
            DataType dt = hal.getParameter(paramIndex).getDataType();
            if (!isLevelOnePointer(dt)) {
                taintWriter.write("[DIRECT TAINT BUT NOT POINTER] Function "
                        + hex((int) hal.getEntryPoint().getOffset()) + " parameter " + paramIndex
                        + " is tainted by DR w\n");
                return;
            }
            taintWriter.write("Function " + hex((int) hal.getEntryPoint().getOffset())
                    + " parameter " + paramIndex + " is tainted by DR w \n");
            taintWriter.flush();
            /*
             * false positives introduced by high pcode are accepted here: transmit
             * functions are skipped by the model consumers anyway, and receive has
             * higher priority and blocks transmit for dual receive/transmit APIs.
             */
            transmitFunctionModels.put((int) hal.getEntryPoint().getOffset(),
                    new Pair<>(paramIndex, targetDR));
        } catch (IOException e) {
            System.out.println("An error occurred in analyzeArgWithMMIOTaint W " + e.getMessage());
        }
    }

    protected void findTaintDriverFunction() {
        for (Function f : drvFunctions.keySet()) {
            for (Pair<Integer, Integer> val : drvFunctions.get(f)) {
                println("Analyzing Driver function: " + hex((int) f.getEntryPoint().getOffset()));
                Integer pc = val.getKey();
                Integer ldrMMIO = val.getValue();
                println("ldr mmio: " + hex(ldrMMIO));
                println("ldr pc: " + hex(pc));
                analyzeArgWithMMIOTaint(f, pc, ldrMMIO); // receive
                analyzeTransmitFunc(f);                   // transmit
                if (monitor.isCancelled()) {
                    return;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    //  MMIO-base overwrite detection & direct MMIO accesses
    // ------------------------------------------------------------------

    protected void findMMIOBaseOverwriteMemoryAndDirectAccessMMIO() {
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            println("findMMIOBaseOverwriteMemoryAndDirectAccessMMIO: " + f.getName());
            CodeUnitIterator cuIter = currentProgram.getListing().getCodeUnits(f.getBody(), true);
            while (cuIter.hasNext()) {
                CodeUnit cu = cuIter.next();
                if (!(cu instanceof Instruction)) {
                    continue;
                }
                Instruction instr = (Instruction) cu;
                String mnemonic = instr.getMnemonicString();
                if (mnemonic.startsWith("str")) {
                    Reference[] storeTos = instr.getOperandReferences(0);
                    Reference[] storeValues = instr.getOperandReferences(1);
                    if (storeTos.length == 0 || storeValues.length == 0) {
                        continue;
                    }
                    for (Reference refTo : storeTos) {
                        Address toAddr = refTo.getToAddress();
                        for (Reference refValue : storeValues) {
                            Integer value = (int) refValue.getToAddress().getOffset();
                            if (isMmio(value) && (value & 0xFF) == 0 && inRam((int) toAddr.getOffset())) {
                                storeMmioBase((int) toAddr.getOffset(), value);
                            }
                        }
                    }
                } else if (mnemonic.startsWith("ldr")) {
                    Reference[] refs = instr.getOperandReferences(1);
                    if (refs.length == 0) {
                        continue;
                    }
                    for (Reference ref : refs) {
                        long value = ref.getToAddress().getOffset();
                        if (isMmio(value)) {
                            drvFunctions.computeIfAbsent(f, k -> new HashSet<>())
                                    .add(new Pair<>((int) instr.getMinAddress().getOffset(), (int) value));
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    //  Function repair
    // ------------------------------------------------------------------

    protected void identifyUncoveredFunctions() {
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            CodeUnitIterator cuIter = currentProgram.getListing().getCodeUnits(f.getBody(), true);
            while (cuIter.hasNext()) {
                CodeUnit cu = cuIter.next();
                if (!(cu instanceof Instruction)) {
                    continue;
                }
                Instruction instr = (Instruction) cu;
                String mnemonic = instr.getMnemonicString();
                if (!mnemonic.equals("b.w") && !mnemonic.equals("b")) {
                    continue;
                }
                for (Reference ref : instr.getOperandReferences(0)) {
                    Address label = ref.getToAddress();
                    println("label is " + hex((int) label.getOffset()) + " f is " + f);
                    println(f.getBody().contains(label) ? "true" : "false");
                    if (inCode((int) label.getOffset()) && !f.getBody().contains(label)) {
                        println("Create function at " + hex((int) label.getOffset()));
                        createFunction(label, String.format("%08x", (int) label.getOffset()));
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    //  Entry point
    // ------------------------------------------------------------------

    @Override
    public void run() throws Exception {
        Instant start = Instant.now();

        config = AnalysisConfig.load(this);
        initTarget();

        File outputDir = new File(config.outputDir);
        if (!outputDir.isDirectory() && !outputDir.mkdirs()) {
            println("[Warning] cannot create output directory: " + outputDir.getAbsolutePath());
        }

        String programName = currentProgram.getName();
        logWriter = new FileWriter(new File(outputDir, programName + ".vlog"));
        writer = new FileWriter(new File(outputDir, programName + ".out"));
        memWriter = new FileWriter(new File(outputDir, programName + ".memout"));
        taintWriter = new FileWriter(new File(outputDir, programName + ".taintout"));
        FileWriter modelWriter = new FileWriter(new File(outputDir, programName + ".json"));

        varTrans = new VarnodeTranslator(currentProgram);

        println("====== HALIXOR: Constant Propagation Analysis ======");
        println("program  : " + programName);
        println("config   : " + config.source);
        println("output   : " + outputDir.getAbsolutePath());

        println("====== Step 1: detect IRQ handlers from the vector table ======");
        identifyIrqHandlerAndInt();

        println("====== Step 2: repair functions for uncovered branch targets ======");
        identifyUncoveredFunctions();

        for (Integer i : intMap.keySet()) {
            println("IRQ " + i + " -> " + hex(intMap.get(i)));
        }

        println("====== Step 3: locate MMIO base references ======");
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator fi = fm.getFunctions(true);
        HashSet<CodeUnit> mmioReferLocations = new HashSet<>();
        while (fi.hasNext()) {
            Function f = fi.next();
            CodeUnitIterator cuIter = currentProgram.getListing().getCodeUnits(f.getBody(), true);
            while (cuIter.hasNext()) {
                CodeUnit cu = cuIter.next();
                Address addr = cu.getMinAddress();
                for (Reference ref : getReferencesFrom(addr)) {
                    Address toAddr = ref.getToAddress();
                    assert mem.contains(toAddr);
                    try {
                        Integer value = mem.getInt(toAddr);
                        if (isMmio(value) && (value & 0xFF) == 0 && cu.getMnemonicString().startsWith("ldr")) {
                            println("Found a reference to a constant: 0x" + String.format("%X", value)
                                    + " at " + String.format("%X", addr.getOffset()));
                            mmioReferLocations.add(cu);
                        }
                    } catch (MemoryAccessException e) {
                        continue;
                    }
                }
            }
        }

        println("====== Step 4.a: find driver functions based on overwritten MMIO base objects ======");
        // globally overwrite hspi(*0x2000faf4) = 0x40003c00 etc. and find the
        // functions that use the peripheral handler
        for (CodeUnit cu : mmioReferLocations) {
            Function f = fm.getFunctionContaining(cu.getMinAddress());
            for (Integer base : binaryEdit(f, cu)) {
                for (Reference ref : getReferencesTo(toAddr(base))) {
                    Address fromAddr = ref.getFromAddress();
                    println("ref " + hex(base) + " at " + hex((int) fromAddr.getOffset()));
                    Function driver = fm.getFunctionContaining(fromAddr);
                    println("find base reference driver function " + " at " + driver);
                    findDriverFunction(driver, null, new HashSet<>());
                }
            }
        }

        println("====== Step 4.b: find MMIO base writes to memory / direct MMIO accesses ======");
        findMMIOBaseOverwriteMemoryAndDirectAccessMMIO();

        println("====== Step 4.c: find driver functions starting from IRQ handlers ======");
        for (Integer i : intMap.keySet()) {
            Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(intMap.get(i)));
            if (f != null) {
                findDriverFunction(f, null, new HashSet<>());
            }
        }

        println("====== Step 5: report functions that overwrite callback functions ======");
        for (Address addr : callBackFuncMap.keySet()) {
            println("Callback function: " + hex((int) addr.getOffset()));
            for (Pair<Integer, Integer> val : callBackFuncMap.get(addr)) {
                println(hex(val.getKey()) + "  -> " + hex(val.getValue()));
            }
        }

        println("====== Step 6: overwrite callback function locations ======");
        // currently only writes one callback function per location
        for (Address addr : callBackFuncMap.keySet()) {
            Pair<Integer, Integer> callback = callBackFuncMap.get(addr).iterator().next();
            println("write callback " + hex((int) addr.getOffset()) + " -> " + hex(callback.getValue()));
            overwriteMemory(callback.getValue() & 0xFFFFFFFE, (int) addr.getOffset(), 4, true);
        }

        println("====== Step 7: find driver functions based on overwritten callback + MMIO base ======");
        // resolve indirect calls through callbacks, then re-run driver discovery
        for (Integer addr : mmioBaseStoreMap.keySet()) {
            for (Reference ref : getReferencesTo(toAddr(addr))) {
                Address fromAddr = ref.getFromAddress();
                findDriverFunction(fm.getFunctionContaining(fromAddr), null, new HashSet<>());
            }
        }

        /*
         * one function may handle multiple peripherals (e.g. huart1 and huart2),
         * so multiple MMIO accesses can appear at the same pc.
         */
        for (Function f : drvFunctions.keySet()) {
            println("Driver function: " + hex((int) f.getEntryPoint().getOffset()));
            for (Pair<Integer, Integer> val : drvFunctions.get(f)) {
                println(hex(val.getKey()) + "  -> " + hex(val.getValue()));
            }
        }

        findTaintDriverFunction();

        println("====== Step 8: generate HAL API models ======");
        ModelGenerator mg = new ModelGenerator(extractFuncModels, transmitFunctionModels, conflictFuncs);
        mg.generateFunctionModel(modelWriter);
        modelWriter.close();

        writer.close();
        memWriter.close();
        taintWriter.close();

        println("====== Done ======");
        println("Elapsed time: " + Duration.between(start, Instant.now()).toSeconds() + " seconds");
        logWriter.close();
    }
}
