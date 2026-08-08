package Taint;

import Util.StringUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.util.HashMap;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;

public class TaintPath {

    public List<PcodeOp> path;
    public List<Address> trace;

    public TaintPath() {
        path = new ArrayList<>();
        trace = new ArrayList<>();
    }

    public void addToPath(PcodeOp p) {
        path.add(p);
    }

    public void addPcToPath(Address pc) {
        trace.add(pc);
    }

    public boolean containsPath(PcodeOp p) {
        for (PcodeOp op: path) {
            if (p.toString().equals(op.toString()))
                return true;
        }
        return false;
    }

    public boolean pathEmpty() {
        return path.size() == 0;
    }

    // EXTENDED: check if the last taint one is a store op
    public boolean isLastStore(){
        if (path.size() < 1) return false;
        return path.get(path.size()-1).getMnemonic().equals("STORE");
    }

    public boolean hasPtrAdd() {
        for (PcodeOp op: path) {
            if (op.getMnemonic().equals("PTRADD"))
                return true;
        }
        return false;
    }

    // find the index of varnode that get tainted in the op
    public int getTaintInputIndex(PcodeOp op, String originalTaint) { 
        for (int i = 0; i < path.size(); i++) {
            if (path.get(i) == op) {
                if (i == 0) {
                    int ind = 0;
                    for (Varnode v: op.getInputs()) {
                        if (v.toString().equals(originalTaint)) {
                            return ind;
                        }
                        ind++;
                    }
                } else {
                    PcodeOp lastop = path.get(i-1);
                    Varnode lastopOutput = lastop.getOutput();
                    int ind = 0;
                    for (Varnode v: op.getInputs()) {
                        if (v.toString().equals(lastopOutput.toString())) {
                            return ind;
                        }
                        ind++;
                    }
                }
            }
        } 
        return -1;
    }

    // EXTENDED: find the index of varnode that get tainted in the Store
    // i. e. the destination or source is tainted
    public int getTaintInputIndexAtLast(String originalTaint) {
        if (path.size() == 0) {
            return -1;
        } else if (path.size() == 1){
            PcodeOp op = path.get(0);
            int ind = 0;
            for (Varnode v: op.getInputs()) {
                if (v.toString().equals(originalTaint)) {
                    return ind;
                }
                ind++;
            } 
        } else {
            PcodeOp lastlastop = path.get(path.size()-2);
            PcodeOp lastop = path.get(path.size()-1);
            Varnode lastlastopOutput = lastlastop.getOutput();
            int ind = 0;
            for (Varnode v: lastop.getInputs()) {
                if (v.toString().equals(lastlastopOutput.toString())) {
                    return ind;
                }
                ind++;
            } 
        }
        return -1;
    }

    @Override
    public TaintPath clone() {

        TaintPath p = new TaintPath();
        p.path = new ArrayList<>(this.path);
        p.trace = new ArrayList<>(this.trace);
        return p;
    }
}
