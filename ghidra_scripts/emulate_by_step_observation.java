//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Objects;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import ghidra.app.emulator.EmulatorHelper;

import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;

import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;

import ghidra.util.exception.CancelledException;

import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.app.decompiler.*;


public class emulate_by_step_observation extends GhidraScript {

    public static int x86 = 8;

    public class InstructionAnalyzer {
        private Program program;

        public InstructionAnalyzer(Program program) {
            this.program = program;
        }

        public String getRegister(Address address, int operandIndex) {
            Instruction instr = getInstructionAt(address);
            if (instr == null) {
                throw new RuntimeException("No instruction at the specified address.");
            }
            // get first operand
            // int operandIndex = 0;
            String registerName = null;
            if (instr.getNumOperands() > operandIndex) {
                int operandType = instr.getOperandType(operandIndex);
                registerName = instr.getDefaultOperandRepresentation(operandIndex);
            } else {
                println("The instruction does not have a first operand.");
            }
            return registerName;
        } 
    }

    public class hashvaluesAnalyzer {
        private Program program;
        private HashMap<Address, Long> hashValues = new HashMap<>();
        private DecompInterface decomplib;
        private HighFunction highFunction;

        public hashvaluesAnalyzer(Program program) {
            this.program = program;
            this.decomplib = new DecompInterface();
            this.decomplib.openProgram(program);
        }

        private HighFunction getHighFunction(Address address) {
            Function function = this.program.getFunctionManager().getFunctionContaining(address);
            HighFunction highFunction = null;
            DecompileResults results = this.decomplib.decompileFunction(function, 30, monitor);
            if (!results.decompileCompleted()) {
                println("Decompilation failed.");
            }
            highFunction = results.getHighFunction();
            if (highFunction == null) {
                println("HighFunction is null.");
            }
            return highFunction;
        }

        // private Scalar getScalarAsParam(int index) {


        // } 


        public HashMap<Scalar, Address> analyzeAllInstructions() {
            HashMap<Scalar, Address> hashVaules = new HashMap<>();
            Listing listing = this.program.getListing();
            InstructionIterator instructions = listing.getInstructions(true);

            while (instructions.hasNext()){
                Instruction instr = instructions.next();
                int numOperands = instr.getNumOperands();
                Address currentAddress = instr.getAddress();

                for (int i = 0; i < numOperands; i++) {
                    int opType = instr.getOperandType(i);
                    if (OperandType.isScalar(opType)) {
                        Scalar scalar = instr.getScalar(i);
                        if (isDWORD(scalar) && !scalar.isSigned()) hashVaules.put(scalar, currentAddress);
                    } else if (OperandType.isDataReference(opType)) {
                        Reference ref = instr.getPrimaryReference(i);
                        if (ref.isMemoryReference()) {
                            Address toAddr = ref.getToAddress();
                            Data data = listing.getDefinedDataAt(toAddr);
                            if (data != null && data.getValue() != null) {
                                Object value = data.getValue();
                                if (value instanceof Scalar) {
                                    Scalar dat_scalar = (Scalar) value;
                                    if (isDWORD(dat_scalar) && !dat_scalar.isSigned()) hashVaules.put(dat_scalar, currentAddress);
                                }
                            }
                        }
                    }
                }
            }
            return hashVaules;
        }

        private boolean isDWORD(Scalar scalar) {
            return scalar.bitLength() == 32;
        }

        private Scalar getOperandValue(Instruction instr, int index) {
            Scalar scalar = null;
            int operandType = instr.getOperandType(index);
            // scalar or dat or param
            if (OperandType.isScalar(operandType)) {
                // if the operand is scalar
                return instr.getScalar(index);
            }
            else if (OperandType.isDataReference(operandType)) {
                // if the operand is memory reference
                Reference ref = instr.getPrimaryReference(index);
                if (ref.isMemoryReference()) {
                    Address toAddr = ref.getToAddress();
                    Data data = this.program.getListing().getDefinedDataAt(toAddr);
                    if (data != null && data.getValue() != null) {
                        Object value = data.getValue();
                        if (value instanceof Scalar) {
                            return scalar = (Scalar) value;
                        }
                    }
                }
            }
            else if ((OperandType.isDynamic(operandType) & OperandType.isAddress(operandType)) | OperandType.isRegister(operandType) ) {
                // chase varnode and check if it was param
                Address currentAddr = instr.getMinAddress();
                // println("dynamic address");
                // DecompInterface decomplib = new DecompInterface();
                // decomplib.openProgram(currentProgram);
                // Function func = currentProgram.getFunctionManager().getFunctionContaining(currentAddr);
                // DecompileResults results = decomplib.decompileFunction(func, operandType, monitor);
                // if (!results.decompileCompleted()) {
                //     println("Decompilation failed.");
                // }
                // HighFunction highFunction = results.getHighFunction();
                // if (highFunction == null) {
                //     println("HighFunction is null.");
                // }
                // println("highFunction: " + highFunction.toString());
                // println("address: " + currentAddr.toString());
                // println("num:" + highFunction.getNumVarnodes());
                Iterator <PcodeOpAST> pcodeOp = highFunction.getPcodeOps(currentAddr);
                PcodeOpAST pcode = pcodeOp.next();
                // println("pcode: " + pcode.toString());
                Varnode var = pcode.getInput(index);
                String varName = var.getHigh().getName();
                // println("varName: " + varName);
                // check name starts with param, and get the index of param (for instance, param_1 -> 1)
                int paramIndex = -1;
                if (!varName.startsWith("param")) {
                    // if the variable name is not param_, we ignore it 
                    return null;
                }
                paramIndex = Integer.parseInt(varName.substring(6));
                // println("paramIndex: " + paramIndex);
                Reference [] callers = getReferencesTo(highFunction.getFunction().getEntryPoint());
                for (Reference caller : callers) {
                    // println("caller: " + caller.toString());
                    if (!caller.getReferenceType().isCall()) continue;
                    Function callerFunc = getFunctionContaining(caller.getFromAddress());
                    HighFunction callerHighFunc = this.decomplib.decompileFunction(callerFunc, 30, monitor).getHighFunction();
                    Iterator<PcodeOpAST> callerPcodeOps = callerHighFunc.getPcodeOps(caller.getFromAddress());
                    while (callerPcodeOps.hasNext()) {
                        // ignore anything other than "CALL"
                        PcodeOpAST callerPcode = callerPcodeOps.next();
                        if (!callerPcode.getMnemonic().equals("CALL")) continue;
                        // println("callerPcode: " + callerPcode.toString());
                        int numParam = callerPcode.getNumInputs();
                        if (numParam <= paramIndex) continue;
                        Varnode varParam = callerPcode.getInput(paramIndex);
                        // println("varParam: " + varParam.toString());
                        Address varParamAddr = varParam.getPCAddress();
                        Instruction ins = getInstructionAt(varParamAddr);
                        // println("opRef" + ins.getOperandRefType(1));
                        Reference ref = ins.getPrimaryReference(1);
                        if (ref == null) continue;
                        Address toAddr = ref.getToAddress();
                        Iterator<Data> datas = this.program.getListing().getData(toAddr, true);
                        while (datas.hasNext()) {
                            Data data = datas.next();
                            if (data.getValue() instanceof Scalar) {
                                Scalar scalarAtMemory = (Scalar) data.getValue();
                                if (scalarAtMemory.getValue() == 0) break;
                                // println("scalarAtMemory: " + scalarAtMemory.toString());
                                // return scalarAtMemory
                            }
                        }
                        // println("" + toAddr.toString());
                        // Data data = this.program.getListing().getDataAt(toAddr);
                        // println("" + data.toString());
                        // data = this.program.getListing().getDefinedDataAfter(toAddr);
                        // println("" + data.toString());
                        // Object[] obs = ins.getInputObjects();
                        // for (Object ob : obs) {
                        //     println("ob type: " + ob.getClass().getName());
                        // }   
                    }
                }
                // getParameterScalar(paramIndex);

                // AddressSpace addressSet = highFunction.getAddressFactory().get 
                // Iterator<VarnodeAST> varNodes = highFunction.getVarnodes(addressSet);
            //     if (varNodes == null) {
            //         println("varnodes is null.");
            //     }
            //     while (varNodes.hasNext()) {
            //         println("varnode: ");
            //         VarnodeAST varNode = varNodes.next();
            //         println("varnode: " + varNode.toString());
            //     }
            }
            // else if (OperandType.isRegister(operandType)) {
            //     // Todo: 
            // }
            return scalar;
        }

        private List<Scalar> handleScalarOperand(Instruction instr, int index) {
            List<Scalar> scalarList = new ArrayList<>();
            Scalar scalar = instr.getScalar(index);
            if (scalar != null) {
                scalarList.add(scalar);
            }
            return scalarList;
        }

        private List<Scalar> handleDataReferenceOperand(Instruction instr, int index) {
            List<Scalar> scalarList = new ArrayList<>();
            Reference ref = instr.getPrimaryReference(index);

            if (ref != null && ref.isMemoryReference()) {
                Address toAddr = ref.getToAddress();
                Data data = this.program.getListing().getDefinedDataAt(toAddr);
                Scalar scalar = getScalarFromData(data);
                if (scalar != null) {
                    scalarList.add(scalar);
                }
            }
            return scalarList;
        }

        private List<Scalar> handleDynamicOrRegisterOperand(Instruction instr, int index) {
            Address currentAddr = instr.getMinAddress();
            HighFunction highFunction = getHighFunctionForInstruction(currentAddr);
            
            if (highFunction == null) {
                return null;
            }

            Varnode var = getVarnodeFromPcode(highFunction, currentAddr, index);

            if (var == null || !isParameterVarnode(var)) {
                return null;
            }

            int paramIndex = getPramIndexFromVarname(var);
            return getScalarForParameter(highFunction, paramIndex);
        }

        private Scalar getScalarFromData(Data data) {
            if (data != null && data.getValue() instanceof Scalar) {
                return (Scalar) data.getValue();
            }
            
            return null;
        }

        private HighFunction getHighFunctionForInstruction(Address addr) {
            Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
            DecompileResults results = this.decomplib.decompileFunction(func, 30, monitor);

            return results.decompileCompleted() ? results.getHighFunction() : null;
        }

        private Varnode getVarnodeFromPcode(HighFunction highFunction, Address addr, int index) {
            Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps(addr);
            if (pcodeOps.hasNext()) {
                // Todo: we consider only the first pcode operation
                PcodeOpAST pcode = pcodeOps.next();
                return pcode.getInput(index);
            }
            return null;
        }

        private boolean isParameterVarnode(Varnode var) {
            String varName = var.getHigh().getName();
            return varName.startsWith("param");
        }

        private int getPramIndexFromVarname(Varnode var) {
            String varName = var.getHigh().getName();
            return Integer.parseInt(varName.substring(6));
        }

        private List<Scalar> getScalarForParameter(HighFunction highFuction, int paramIndex) {
            List<Scalar> scalarList = new ArrayList<>();
            Reference[] callers = getReferencesTo(highFuction.getFunction().getEntryPoint());

            for (Reference caller : callers) {
                if (caller.getReferenceType().isCall()) {
                    Function callerFunc = getFunctionContaining(caller.getFromAddress());
                    HighFunction callerHighFunc = decompileCallerFunction(callerFunc);

                    if (callerHighFunc != null) {
                        List<Scalar> scalars = findScalarInCallerPcode(callerHighFunc, caller, paramIndex);
                        if (!scalars.isEmpty()) {
                            scalarList.addAll(scalars);
                        }
                    }
                }
            }

            return scalarList;
        }

        private HighFunction decompileCallerFunction(Function func) {
            DecompileResults results = this.decomplib.decompileFunction(func, 30, monitor);
            return results.decompileCompleted() ? results.getHighFunction() : null;
        }

        private List<Scalar> findScalarInCallerPcode(HighFunction highFunction, Reference caller, int paramIndex) {
            List<Scalar> scalarList = new ArrayList<>();
            Iterator<PcodeOpAST> callerPcodeOps = highFunction.getPcodeOps(caller.getFromAddress());

            while (callerPcodeOps.hasNext()) {
                PcodeOpAST pcodeOp = callerPcodeOps.next();
                if (!pcodeOp.getMnemonic().equals("CALL")) continue;
                
                if (pcodeOp.getNumInputs() > paramIndex) {
                    Varnode varParam = pcodeOp.getInput(paramIndex);

                    if (varParam.isConstant()) scalarList.add(new Scalar(varParam.getSize() * 8, varParam.getOffset()));
                    
                    if (varParam.isUnique() || varParam.isAddress()) {
                        Address paramAddr = varParam.getPCAddress();
                        Instruction instr = getInstructionAt(paramAddr);

                        if (instr != null) {
                            List<Scalar> scalars = getScalarFromInstruction(instr);
                            scalarList.addAll(scalars);
                        }
                    }
                }
            }

            return scalarList;
        }
        
        private List<Scalar> getScalarFromInstruction(Instruction instr) {
            List<Scalar> scalarList = new ArrayList<>();
            Reference ref = instr.getPrimaryReference(1);

            if (ref != null) {
                Address toAddr = ref.getToAddress();
                Iterator<Data> dataIterator = this.program.getListing().getData(toAddr, true);
                // println("toAddr: " + toAddr.toString());
                while (dataIterator.hasNext()) {
                    Data data = dataIterator.next();
                    Scalar scalar = getScalarFromData(data);
                    if (scalar != null) {
                        if (scalar.getValue() == 0) break;
                        scalarList.add(scalar);
                    }
                }
            }
            
            return scalarList;
        }

        private List<Scalar> getOperandValues(Instruction instr, int index) {
            int operandType = instr.getOperandType(index);

            if (OperandType.isScalar(operandType)) {
                return handleScalarOperand(instr, index);
            } else if (OperandType.isDataReference(operandType)) {
                return handleDataReferenceOperand(instr, index); 
            } else if ((OperandType.isDynamic(operandType) & OperandType.isAddress(operandType)) | OperandType.isRegister(operandType)) {
                return handleDynamicOrRegisterOperand(instr, index);
            }

            return Collections.emptyList();
        }

        private void addScalarToMap(Address addr, Scalar scalar, HashMap<Address, List<Scalar>> map) {
            map.computeIfAbsent(addr, k -> new ArrayList<>()).add(scalar);
        }

        // this implementation is not perfect, because hash value is passed by parameter. must chase the value
        // find CMP instruction, and get the value
        // if the value is located in DAT, get the value from DAT Address
        // if the value is passed by register, chase the register value
        public HashMap<Address, List<Scalar>> analyzeInstructions(Address startAddress, Address endAddress) {
            Listing listing = this.program.getListing();
            AddressSetView addressSet = new AddressSet(startAddress, endAddress);
            InstructionIterator instructions = listing.getInstructions(addressSet, true);
            HashMap<Address, List<Scalar>> hashCandidates = new HashMap<>();
            // 関数呼び出しやJMP先には対応していない
            // check operand, and if it is scalar, get the value, and if it is DAT , refer to and get the value
            while(instructions.hasNext()) {
                Instruction instr = instructions.next();
                Address currentAddress = instr.getMinAddress();
                int numOperands = instr.getNumOperands();
                String opCode = instr.getMnemonicString();
                // println(opCode);
                highFunction = getHighFunction(currentAddress);
                if (opCode.equals("CMP")) {
                    // println("IN CMP");
                    for (int i = 0; i < numOperands; i++){
                        // may getOperandValues return null
                        List<Scalar> scalars = getOperandValues(instr, i);
                        if (scalars == null) continue;
                        for (Scalar scalar : scalars) {
                            addScalarToMap(currentAddress, scalar, hashCandidates);
                        }
                    }
                }
            }
            // for (Address addr : hashCandidates.keySet()) {
            //     println("Address: " + addr.toString());
            //     for (Scalar scalar : hashCandidates.get(addr)) {
            //         println("scalar: " + scalar.toString());
            //     }
            // }
            return hashCandidates;
        }
    }

    public class EmulationManager {
        private EmulatorHelper emu;
        private Address startAddress;
        private Address endAddressOfHashing;
        private String regAtStart;
        private String regStoredHash;

        public EmulationManager(Program program, Address startAddress) {
            this.emu = new EmulatorHelper(program);
            this.startAddress = startAddress;
            this.endAddressOfHashing = null;
            this.regStoredHash = null;

            analyzeRegAtStart();
            emu.writeRegister(emu.getPCRegister(), startAddress.getOffset());
        }

        private void analyzeRegAtStart() {
            Instruction instr = getInstructionAt(this.startAddress);
            if (instr == null) {
                throw new RuntimeException("No instruction at the specified address.");
            }
            String registerName = null;
            int operandType = instr.getOperandType(0);
            if (OperandType.isRegister(operandType)) registerName = instr.getDefaultOperandRepresentation(0);
            if (registerName == null) {
                throw new RuntimeException("No register at the specified address.");
            }
            this.regAtStart = registerName;
        }

        private void identifyRangeOfHashing(String apiName, HashMap<Address, List<Scalar>> hashCandidates) {
            Address retAddress = getFunctionContaining(startAddress).getBody().getMaxAddress();
            // emu.setBreakpoint(retAddress);

            Address stringAddress = toAddr(0xa00000);
            emu.writeMemoryValue(stringAddress, 0x32, 0x00);
            emu.writeMemory(stringAddress, apiName.getBytes());        
            emu.writeRegister(regAtStart, stringAddress.getOffset());


            String regName = null;
            boolean hashFound = false;
            while(!monitor.isCancelled()) {
                currentAddress = emu.getExecutionAddress();
                Instruction instr = getInstructionAt(currentAddress);
                // println("current: " + currentAddress.toString());
                int numOperands = instr.getNumOperands();
                for (int i=0; i<numOperands; i++) {
                    if(OperandType.isRegister(instr.getOperandType(i))) {
                        regName = instr.getDefaultOperandRepresentation(i);
                        // printReg(emu, regName);
                        if (checkHash(emu, regName, hashCandidates)) {
                            println("[+] First Emulation, result equals hashCandidate: 0x" + emu.readRegister(regName).toString(16) + " -> address: " + currentAddress);
                            this.regStoredHash = regName;
                            this.endAddressOfHashing = currentAddress;
                            hashFound = true;
                            break;
                        }
                    }    
                }

                // if currentAddress doesn't reach to retAddress, or hash value is found, continue
                if (currentAddress == retAddress || hashFound) break;
                
                try {
                    emu.step(monitor);
                } catch (CancelledException e) {
                    println("Emulation step was cancelled: " + e.getMessage());
                    break;
                }

            }
        }

        private BigInteger caliculateHashValue(String apiName) {
            BigInteger hash = null;
            emu.writeRegister(emu.getPCRegister(), startAddress.getOffset());
            emu.setBreakpoint(this.endAddressOfHashing);

            Address stringAddress = toAddr(0xa00000);
            emu.writeMemoryValue(stringAddress, 0x32, 0x00);
            emu.writeMemory(stringAddress, apiName.getBytes());
            emu.writeRegister(regAtStart, stringAddress.getOffset());

            while(!monitor.isCancelled()) {
                currentAddress = emu.getExecutionAddress();

                if (emu.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT) {
                    try {
                        emu.step(monitor);
                    } catch (CancelledException e) {
                        println("Emulation step was cancelled: " + e.getMessage());
                        break;
                    }
                }
                else {
                    hash = emu.readRegister(this.regStoredHash);
                    break;
                }

            }

            return hash;

        }
    }

    @Override
    protected void run() throws Exception {
        /* setup env from DBI information */
        Address startAddress = toAddr(0x40131e);
        // Address startAddress = toAddr(0x401342);
        // below is conti
        // Address startAddress = toAddr(0x4033f2);        

        // Address endAddress = toAddr(0x401349);
        Address endAddress = toAddr(0x401358);
        // below is conti
        // Address endAddress = toAddr(0x403413);

        // Address maxAddress = getFunctionContaining(startAddress).getBody().getMaxAddress();

        hashvaluesAnalyzer hashAnalyzer = new hashvaluesAnalyzer(currentProgram);
        HashMap<Address, List<Scalar>> hashCandidates = hashAnalyzer.analyzeInstructions(startAddress, endAddress);

        // if (true) {
        //     throw new RuntimeException("end");
        // }

        // HashMap<Scalar, Address> hashCandidates = hashAnalyzer.analyzeAllInstructions();

        // print hashCandidtates like [0x10000, 0x300000, ...]
        


        List<String> candidates = new ArrayList<String>();
        for (Address addr : hashCandidates.keySet()) {
            // println("Address: " + addr.toString());
            for (Scalar scalar : hashCandidates.get(addr)) {
                candidates.add(scalar.toString());
            }
        }
        println("[+] hashCandidates: " + Arrays.toString(candidates.toArray()));


        /* analyze memory-access instruction */
        InstructionAnalyzer analyzer = new InstructionAnalyzer(currentProgram);
        String dstRegisterAtStart = analyzer.getRegister(startAddress, 0);
        // if dstRegister is null, then the program will be cancelled
        if (dstRegisterAtStart == null) {
            throw new RuntimeException("register is null?");
        }

        /* identify ranges of Hashing by step emulating */
        EmulationManager emuManager = new EmulationManager(currentProgram, startAddress);
        emuManager.identifyRangeOfHashing("CreateThread", hashCandidates);
        // println("[!] regStoredHash: " + emuManager.regStoredHash);
        // println("[!] start: " + emuManager.startAddress.toString());
        // println("[!] end: " + emuManager.endAddressOfHashing.toString());

        /* parse json */
        String dir = getSourceFile().getParentFile().getParentFile().getAbsolutePath();
        // String filePath = dir + "\\dlls\\exports.json";
        String filePath = dir + "/dlls/exports.json";
        HashMap<String, List<String>> dllApiMap = readDBJson(filePath);
        
        println("[+] now caliculating hash values...");
        HashMap<String, BigInteger> hashDB = new HashMap<>();
        // println("size: " + dllApiMap.size());
        for (String dll: dllApiMap.keySet()) {
            // println("DLL: " + dll);
            for (String api: dllApiMap.get(dll)) {
                BigInteger hash = emuManager.caliculateHashValue(api);
                hashDB.put(api, hash);
                // println("  API: " + api + " -> hash: " + hash.toString(16));
            }
                // println("  API: " + api);
        }
        println("[+] caliculation done!");

        println("[+] now resolving API names from hash values...");
        searchHashValues(hashDB, hashCandidates);



    }

    // public void printReg(EmulatorHelper emu) {
    //     List <Register> programRegisters = currentProgram.getProgramContext().getRegisters();
    //     for (Register reg: programRegisters) {
    //         // hidden registers are like PC, SP, etc.
    //         if (!reg.isHidden()) {
    //             // if reg is eax or ebx
    //             if (reg.getName().equals("EAX")){
    //                 println(reg.getName() + ": 0x" + emu.readRegister(reg).toString(16));
    //             }
    //         }
    //     }
    // }

    public void printReg(EmulatorHelper emu, String reg) {
        println(reg + ": 0x" + emu.readRegister(reg).toString(16));
    }

    public boolean checkHash(EmulatorHelper emu, String reg, HashMap<Address, List<Scalar>> candidates) {
        BigInteger result = emu.readRegister(reg);
        for (Address addr : candidates.keySet()) {
            for (Scalar scalar : candidates.get(addr)) {
                // long to BigInteger
                BigInteger hashValue = BigInteger.valueOf(scalar.getValue());
                if (result.equals(hashValue)) {
                    // println("[+] First Emulation, hash value found: " + scalar + " -> Address: " + addr);
                    return true;
                }
            }
        }

        return false;
    }

    public HashMap<String, List<String>> readDBJson(String filePath) {
        HashMap<String, List<String>> dllApiMap = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            String currentDLL = null;

            while ((line = reader.readLine()) != null) {
                line = line.trim();

                if (line.startsWith("\"") && line.contains(".dll")) {
                    int startQuote = line.indexOf('"');
                    int endQuote = line.indexOf('"', startQuote + 1);
                    currentDLL = line.substring(startQuote + 1, endQuote);
                    dllApiMap.put(currentDLL, new ArrayList<>());
                }

                if (line.startsWith("\"") && currentDLL != null) {
                    int startQuote = line.indexOf('"');
                    int endQuote = line.indexOf('"', startQuote + 1);
                    String apiName = line.substring(startQuote + 1, endQuote);
                    dllApiMap.get(currentDLL).add(apiName);
                }
            }
        } catch (IOException e) {
            println("Failed to read the file: " + e.getMessage());
        }

        return dllApiMap;
    }

    public void searchHashValues(HashMap<String, BigInteger> hashDB, HashMap<Address, List<Scalar>> hashCandidates) {
        for (Address addr : hashCandidates.keySet()) {
            for (Scalar scalar : hashCandidates.get(addr)) {
                for (String api : hashDB.keySet()) {
                    if (hashDB.get(api).equals(BigInteger.valueOf(scalar.getValue()))) {
                        println("[+] API: " + api + " -> hash: 0x" + hashDB.get(api).toString(16) + " -> Address: " + addr);
                    }
                }
            }
        }
    }

}