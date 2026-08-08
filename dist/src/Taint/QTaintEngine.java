package Taint;

import Constant.Configs;
import Constant.Constants;
import Main.Decompiler; 
import Util.BlockUtil;
import Util.FunctionUtil;
import Util.PCodeUtil;
import Util.AddressUtil;
// import Util.NumericUtil;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import org.json.JSONArray;
import org.json.JSONObject; 

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.HashSet;
import javafx.util.Pair;

import ghidra.app.script.GhidraScript; 
/**
 * Taint analysis engine running of Ghidra's PCode level
 * Input: inputLocations (HashMap)
 */
public class QTaintEngine {

    Address start;
    Function taintFunction;
    String taintExpression;
    List<TaintPath> paths;
    HashMap<Address, String> inputLocations;
    public JSONObject jsonResult = new JSONObject();
    public String outputStr = "";
    protected Program currentProgram;
    protected GhidraScript script;

    public QTaintEngine(Address startAdd, String taintExp, Program program, GhidraScript script) {
        start = startAdd;
        taintExpression = taintExp;
        paths = new ArrayList<>();
        inputLocations = new HashMap<>();
        currentProgram = program; 
        this.script = script;

        inputLocations.put(start, taintExpression);
        identifyCorrectInputLoc();

    }

    protected void identifyCorrectInputLoc() {
        Program program = currentProgram;

        Function currentFunc = FunctionUtil.getFunctionWith(program, start);
        DecompileResults decompileResults = Decompiler.decompileFunc(currentProgram, currentFunc);
        HighFunction highFunction = decompileResults.getHighFunction();
        
        
        Iterator<PcodeOpAST> asts = highFunction.getPcodeOps();

        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            long a = ast.getSeqnum().getTarget().getUnsignedOffset();
            if (ast.getSeqnum().getTarget().getUnsignedOffset() < start.getUnsignedOffset())
                continue; // loop until we reach the starting point
            Varnode [] inputs = ast.getInputs();
            Varnode output = ast.getOutput();
            if (ast.getMnemonic().equals("STORE")) {
                Varnode input2 = ast.getInput(2);
                if(input2.toString().equals(taintExpression)) {
                    // start = ast.getSeqnum().getTarget();
                    inputLocations.put(ast.getSeqnum().getTarget(), ast.getInput(1).toString());
                    return;
                }
            } else {
                // only find the first occassion
                for (Varnode input: inputs) {
                    if (input.toString().equals(taintExpression) && output != null) {
                        // start = ast.getSeqnum().getTarget();
                        inputLocations.put(ast.getSeqnum().getTarget(), output.toString());
                        return;
                    }
                }
            }
        }
    }

    protected Address toAddr(Integer addr) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
    }

    // re-write the taint below
    public void taintWithSingleReg() {
        if (taintExpression.equals(""))
            return;

        Program program = currentProgram;
        Function startFunc = FunctionUtil.getFunctionWith(program, start);

        CodeBlock[] currentBlocks = BlockUtil.locateBlockWithAddress(program, startFunc.getEntryPoint());
        if (currentBlocks == null || currentBlocks.length == 0) {
            script.println("Error: block not found for address: " + startFunc.getEntryPoint());
            return;
        }
        // dumpInputLocations("before identifyInputLoc");
        identifyInputLoc();
        // dumpInputLocations("after identifyInputLoc");
        identifyIndirectInputLoc();
        // dumpInputLocations("after identifyIndirectInputLoc");
        startTaint();
    }


    protected int getIndexOfVar(PcodeOp op, Varnode var) {
        for (int i=0; i<op.getNumInputs(); ++i) {
            if (op.getInput(i).toString().equals(var.toString())) {
                return i;
            }
        }
        return -1;
    }

    protected boolean inCode(Integer addr) {
        // generally code is in the first memory block
        return currentProgram.getMemory().getFirstRange().contains(toAddr(addr));
    }

    protected boolean inRam(Integer addr) {
        int i = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            // skip the first
            if (i == 0) {
                i++;
                continue;
            }
            if (block.isInitialized() && block.contains(toAddr(addr))) {
                return true;
            }
        }
        return false;
    }

    /* 
    * Check if the taint path of MMIO hit the store endpoint
    * @param op: the current pcode operation
    * @param storeMap: the map of store endpoints of buffer
    * @param taintIndex: the index of MMIO taint
     */
    protected boolean checkMMIOHitStore(PcodeOp op, HashMap<Address, HashSet<Pair<PcodeOp, Varnode> > > storeMap, int taintIndex) { 
        Address loc = op.getSeqnum().getTarget(); 
         
        if (storeMap.containsKey(loc)) {
            HashSet<Pair<PcodeOp, Varnode> > vars = storeMap.get(loc); 
            for (Pair<PcodeOp, Varnode> var: vars) {
                PcodeOp current = var.getKey(); 
                if (current.toString().equals(op.toString()) && current.getMnemonic().equals("STORE")) { 
                    int indexOfStore = getIndexOfVar(current, var.getValue());
                    if (indexOfStore != taintIndex) {
                        
                        // Receive only:
                        Varnode storeNode = op.getInput(1);
                        if (storeNode.getAddress().getAddressSpace().getName().equals("ram")
                        ) {
                            Integer offset = (int) storeNode.getOffset();
                            if (inCode(offset)) {
                                try {
                                    Memory mem = currentProgram.getMemory();
                                    Integer addr = mem.getInt(toAddr(offset), false);
                                    //XXX: if it is a buffer, it can only be store in ram. not code or mmio.
                                    if (!inRam(addr)) {
                                        continue;
                                    }
                                } catch (MemoryAccessException e) {
                                    script.println("[Warning] a suspicious taint path, still report it as true case");
                                } 
                            }
                        }
                        script.println("Function: " + currentProgram.getFunctionManager().getFunctionContaining(loc).getName()); 
                        script.println(""+ loc + " PcodeOp: " + op.toString());
                        script.println(""+ loc + " MMIO:" + current.getInput(taintIndex).toString()+ " ====> BUFFER" + var.getValue().toString());
                        return true;
                    }
                }
            }
        } 
        return false;
         
    }

    public boolean checkMMIOHitStoreEndpoint(HashMap<Address, HashSet<Pair<PcodeOp, Varnode>> > storeMap) { 
        for (TaintPath p: paths) { 
            for (PcodeOp op: p.path) {
                int taintIndex = p.getTaintInputIndex(op, taintExpression);
                if (checkMMIOHitStore(op, storeMap, taintIndex)) { 
                    return true;
                }
            }
        }
        return false;
    }

    public ArrayList<Integer> checkBufferStoreToMem() {
        ArrayList<Integer> res = new ArrayList<>();
        for (TaintPath p: paths) {
            boolean lastStore = p.isLastStore();
            if (!lastStore) continue;
            int taintInputIndex = p.getTaintInputIndexAtLast(taintExpression);
            // for store, we check if the buffer addr has been written to memory, so it must be source
            if (taintInputIndex != 2) continue;
            Address lastLoc = p.path.get(p.path.size()-1).getSeqnum().getTarget();
            Instruction inst = currentProgram.getListing().getInstructionAt(lastLoc);
            Reference[] ref = inst.getOperandReferences(1);
            if (ref.length != 0) {
                for (Reference r: ref) {
                    Address to = r.getToAddress(); 
                    script.println("At " + lastLoc + " Buffer addr is written to " + to);
                    res.add((int)to.getOffset()); 
                }
            }
        }
        return res;
    }

    public HashMap<Address, HashSet<Pair<PcodeOp, Varnode> > > getTaintEndpointsAtStore() {
    //     jsonResult.put("Function", taintFunction.toString());
    //    jsonResult.put("TaintExpression", taintExpression); 
        HashMap<Address, HashSet<Pair<PcodeOp, Varnode>> > endpoints = new HashMap<>();
        for (TaintPath p: paths) {
            // only apply to store at the end of path
            boolean lastStore = p.isLastStore();
            // boolean hasPtrAdd = p.hasPtrAdd(); // either DR or buffer can be indexed
            // if (!lastStore || hasPtrAdd) continue;
            if (!lastStore) continue;

            int taintInputIndex = p.getTaintInputIndexAtLast(taintExpression); 

            // XXX: interesting point! we reverse load and store information here
            // transmit function, the end point node is 2
            // receive function, the end point node is 1
            if (!(taintInputIndex == 1|| taintInputIndex == 0)) continue; // -> for load
            // if (!(taintInputIndex == 2)) continue; // for store
            
            Address lastLoc = p.path.get(p.path.size()-1).getSeqnum().getTarget();
            if (!endpoints.containsKey(lastLoc)) {
                endpoints.put(lastLoc, new HashSet<>());
            }
            PcodeOp lastOp = p.path.get(p.path.size()-1);
            endpoints.get(lastLoc).add(new Pair<>(lastOp, lastOp.getInput(taintInputIndex)));
        } 
        return endpoints;
    }
    
    public boolean checkTransmitTaintAt( Integer pc /* pc that write to MMIO data */, Integer mmio /* DR */) {
        for (TaintPath p: paths) {
            for (PcodeOp op: p.path) {
                if (op.getSeqnum().getTarget().getUnsignedOffset() == pc) {
                    int taintIndex = p.getTaintInputIndex(op, taintExpression);
                    if (taintIndex == 2 && op.getMnemonic().equals("STORE")) {
                        script.println("At " + Integer.toHexString(pc) + " MMIO:" + op.getInput(taintIndex).toString() + " ====> DR" + Integer.toHexString(mmio));
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public void taint() {

        if (taintExpression.equals(""))
            return;

        Program program = currentProgram;
        Function startFunc = FunctionUtil.getFunctionWith(program, start);

        // locate block at the target function
        CodeBlock[] currentBlocks = BlockUtil.locateBlockWithAddress(program, startFunc.getEntryPoint());
        if (currentBlocks == null || currentBlocks.length == 0) {
            System.out.println("Error: block not found for address: " + startFunc.getEntryPoint());
            return;
        }
        
        identifyInputLoc();
        identifyIndirectInputLoc();
        startTaint();
        evaluateResult();

        /*
        QTaintPath taintPath = new QTaintPath();
        taintPath.addTaintVar(taintExpression);
        CodeBlock currentBlock = currentBlocks[0];
        recursiveTaint(currentBlock, taintPath, new ArrayList<>());

        for (QTaintPath path: allPaths) {
            evaluateEqualExp(path);
        }
        */
    }


    public void identifyInputLoc() {
        Program program = currentProgram;

        taintFunction = FunctionUtil.getFunctionWith(program, start);
        DecompileResults decompileResults = Decompiler.decompileFunc(currentProgram, taintFunction);
        HighFunction highFunction = decompileResults.getHighFunction();


        Iterator<PcodeOpAST> asts = highFunction.getPcodeOps();

        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            long a = ast.getSeqnum().getTarget().getUnsignedOffset();
            if (ast.getSeqnum().getTarget().getUnsignedOffset() < start.getUnsignedOffset())
                continue; // loop until we reach the starting point
            Iterator<PcodeOpAST> o = highFunction.getPcodeOps(ast.getSeqnum().getTarget());
            Varnode[] inputs = ast.getInputs();
            Varnode output = ast.getOutput();

            String exp = PCodeUtil.evaluateVarNode(output);
            if (exp != null && exp.equals(taintExpression)) {
                if (ast.getOutput() == null)
                    continue;
                inputLocations.put(ast.getSeqnum().getTarget(), output.toString());
            }

        }
    }

    // deal with load/store indirect reference
    public void identifyIndirectInputLoc() {
        Program program = currentProgram;

        Function currentFunc = FunctionUtil.getFunctionWith(program, start);
        // DecompileResults decompileResults = Decompiler.decompileFuncRegister(currentProgram, currentFunc);
        DecompileResults decompileResults = Decompiler.decompileFunc(currentProgram, currentFunc);
        HighFunction highFunction = decompileResults.getHighFunction();

        Iterator<PcodeOpAST> asts = highFunction.getPcodeOps();

        List<String> stackExp = new ArrayList<>();

        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            if (ast.getSeqnum().getTarget().getUnsignedOffset() < start.getUnsignedOffset())
                continue; // loop until we reach the starting point
            Varnode[] inputs = ast.getInputs();
            // for (int i=0; i<inputs.length; ++i) {
            String mnem = ast.getMnemonic();

            if (mnem.equals("STORE")) {
                // if (inputs[2] != null) {
                //     testQtRe.println("pc is : " + ast.getSeqnum().getTarget());
                //     testQtRe.println("evaluate " + inputs[2].toString());
                // } 
                
                String expOfSrc = PCodeUtil.evaluateVarNode(inputs[2]); 
                if (expOfSrc!= null && expOfSrc.contains(taintExpression)) { 
                    String expToAdd = PCodeUtil.evaluateVarNode(inputs[1]);
                    if (!stackExp.contains(expToAdd)) { 
                        stackExp.add(expToAdd); 
                    }
                }
            }
            else if (stackExp.size() != 0) {
                String outputExp = PCodeUtil.evaluateVarNode(ast.getOutput());
                if (stackExp.contains(outputExp)) {
                    if (!inputLocations.containsKey(ast.getSeqnum().getTarget()))
                        inputLocations.put(ast.getSeqnum().getTarget(), ast.getOutput().toString());
                }
            }
            // }
        }
    }

    protected void dumpInputLocations(String msg) {
        script.println(msg);
        // dump inputLocations
        for (Address add: inputLocations.keySet()) {
            script.println("Input: " + add + " " + inputLocations.get(add));
        }
    }

    private void startTaint() {
        Program program = currentProgram;

        Function currentFunc = FunctionUtil.getFunctionWith(program, start);
        DecompileResults decompileResults = Decompiler.decompileFunc(currentProgram, currentFunc);
        HighFunction highFunction = decompileResults.getHighFunction(); 
        
        // dumpInputLocations("before taint");

        for (Address add: inputLocations.keySet()) {
            // script.println("Taint: " + add + " " + inputLocations.get(add));
            Iterator<PcodeOpAST> asts = highFunction.getPcodeOps(add);
            // script.println("Taint: " + add + " " + inputLocations.get(add));
            String targetReg = inputLocations.get(add);
            while (asts.hasNext()) {
                // script.println(" anlyze ast ");
                PcodeOpAST ast = asts.next(); 
                // if (ast.getOutput() == null) 
                //     continue; 
                // what if ast is store? let's keep it simple as only one path
                // the input(2) should be the taint expression
                // the input(1) should be the detected varnode in inputLocations
                if (ast.getMnemonic().equals("STORE") && targetReg.equals(ast.getInput(1).toString()) && ast.getInput(2).toString().equals(taintExpression)) { 
                    TaintPath path = new TaintPath();
                    path.addToPath(ast);
                    path.addPcToPath(ast.getSeqnum().getTarget());
                    paths.add(path);
                    break;
                } else if (ast.getOutput() == null){
                    continue;
                } else if (ast.getOutput().toString().equals(targetReg)) { 
                    // start to taint descendants
                    Iterator<PcodeOp> descendants = ast.getOutput().getDescendants();
                    while (descendants.hasNext()) { 
                        // Environment.PCODE_INS_COUNT ++;
                        PcodeOp des = descendants.next();
                        TaintPath path = new TaintPath();
                        path.addToPath(ast);
                        path.addToPath(des);
                        path.addPcToPath(ast.getSeqnum().getTarget());
                        path.addPcToPath(des.getSeqnum().getTarget());
                        recursiveTraverse(des, path);
                    }
                }
            }
        }
    }

    public void evaluateResult() {
       jsonResult.put("Function", taintFunction.toString());
       jsonResult.put("TaintExpression", taintExpression);

        JSONObject allPaths = new JSONObject();
        for (TaintPath p: paths) {
            int count = paths.indexOf(p);
            JSONArray jsonArray = new JSONArray(); 
            for (PcodeOp op: p.path) {
                int index = p.path.indexOf(op);
                String mnem = op.getMnemonic();
                Varnode[] inputs = op.getInputs();
                if (mnem.equals("CALL")) {
                    Function func = FunctionUtil.getFunctionWith(currentProgram, inputs[0].getAddress());
                    StringBuilder tmp = new StringBuilder();
                    tmp.append(op);
                    tmp.append("  ");
                    tmp.append(func.getName());
                    if (func.getName().equals("operator==")) {
                        tmp.append(" ==> ");
                        String exp1 = PCodeUtil.evaluateVarNode(inputs[1]);
                        String exp2 = PCodeUtil.evaluateVarNode(inputs[2]);
                        tmp.append(exp1);
                        tmp.append("=");
                        tmp.append(exp2);
                    }
                    jsonArray.put(tmp.toString()); 
                }
                else if (mnem.equals("INT_EQUAL")) {
                    StringBuilder tmp = new StringBuilder();
                    tmp.append(op);
                    String exp1 = PCodeUtil.evaluateVarNode(inputs[0]);
                    String exp2 = PCodeUtil.evaluateVarNode(inputs[1]);
                    tmp.append(" ==> ");
                    tmp.append(exp1);
                    tmp.append("=");
                    tmp.append(exp2);
                    jsonArray.put(tmp.toString());
                }
                else {
                    jsonArray.put(p.trace.get(index).toString() + " " + op.toString());  
                } 

            }
            allPaths.put(String.valueOf(count), jsonArray);
        }
       jsonResult.put("paths", allPaths);
       outputStr = jsonResult.toString(4);
       script.println(outputStr);
    }


    public void recursiveTraverse(PcodeOp current, TaintPath currentPath) {

        if (current == null || current.getOutput() == null) {
            // no outputStr, search ends
            paths.add(currentPath);
            return;
        }

        Iterator<PcodeOp> descendants = current.getOutput().getDescendants();

        if (!descendants.hasNext()) {
            // no descendants, search ends
            paths.add(currentPath);
            return;
        }

        while (descendants.hasNext()) {
            PcodeOp des = descendants.next();
            if (des.getMnemonic().equals("MULTIEQUAL"))
                continue;
            TaintPath newPath = currentPath.clone();
            newPath.addToPath(des);
            newPath.addPcToPath(des.getSeqnum().getTarget());
            recursiveTraverse(des, newPath);
        }
    }



}
