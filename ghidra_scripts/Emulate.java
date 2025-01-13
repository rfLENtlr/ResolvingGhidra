//attempt to resolve API Names from hash values
//@author rfLENtlr 
//@category API_Hashing
//@keybinding 
//@menupath 
//@toolbar 

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.math.BigInteger;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

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
import ghidra.app.decompiler.*;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

public class Emulate extends GhidraScript {

    public class ScalarWithAddress {
        private Scalar scalar;
        private Address addr;

        public ScalarWithAddress(Scalar scalar, Address addr) {
            this.scalar = scalar;
            this.addr = addr;
        }

        public Scalar getScalar() {
            return scalar;
        }
    
        public Address getAddress() {
            return addr;
        }
    }

    public class hashvaluesAnalyzer {
        private Program program;
        private DecompInterface decomplib;

        public hashvaluesAnalyzer(Program program) {
            this.program = program;
            this.decomplib = new DecompInterface();
            this.decomplib.openProgram(program);
        }

        // return <addr, scalar>
        private List<ScalarWithAddress> handleScalarOperand(Instruction instr, int index) {
            List<ScalarWithAddress> scalarList = new ArrayList<>();
            Scalar scalar = instr.getScalar(index);
            if (scalar != null) {
                if (scalar.getValue() > 0){
                    scalarList.add(new ScalarWithAddress(scalar, instr.getMinAddress()));
                }
            }
            return scalarList;
        }

        private List<ScalarWithAddress> handleDataReferenceOperand(Instruction instr, int index) {
            List<ScalarWithAddress> scalarList = new ArrayList<>();
            Reference ref = instr.getPrimaryReference(index);

            if (ref != null && ref.isMemoryReference()) {
                Address toAddr = ref.getToAddress();
                Iterator<Data> dataIterator = this.program.getListing().getData(toAddr, true);

                while (dataIterator.hasNext()) {
                    Data data = dataIterator.next();
                    Scalar scalar = getScalarFromData(data);
                    if (scalar != null) {
                        // excluding 0xff, 0x1
                        if (scalar.getValue() < 0 || scalar.bitLength() != 32) break;
                        println("scalar: " + scalar.toString());
                        scalarList.add(new ScalarWithAddress(scalar, toAddr));
                    }
                }
                // Data data = this.program.getListing().getDefinedDataAt(toAddr);
                // Scalar scalar = getScalarFromData(data);
                // if (scalar != null) {
                //     if (scalar.getValue() > 0)
                //         scalarList.add(new ScalarWithAddress(scalar, toAddr));
                // }
            }
            return scalarList;
        }

        private List<ScalarWithAddress> handleDynamicOrRegisterOperand(Instruction instr, int index) {
            Address currentAddr = instr.getMinAddress();
            HighFunction highFunction = getHighFunctionForInstruction(currentAddr);
            
            if (highFunction == null) {
                return null;
            }

            Varnode var = getVarnodeFromPcode(highFunction, currentAddr, index);
            // println("var: " + var.toString());

            if (var == null || !isParameterVarnode(var)) {
                // println("var is null or not parameter");
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
            HighVariable highVar = var.getHigh();
            if (highVar == null) return false;
            String varName = highVar.getName();
            // println("varName: " + varName);
            return varName.startsWith("param");
        }

        private int getPramIndexFromVarname(Varnode var) {
            String varName = var.getHigh().getName();
            return Integer.parseInt(varName.substring(6));
        }

        /* try to extract an argument from caller functions */
        private List<ScalarWithAddress> getScalarForParameter(HighFunction highFuction, int paramIndex) {
            List<ScalarWithAddress> scalarList = new ArrayList<>();
            Reference[] callers = getReferencesTo(highFuction.getFunction().getEntryPoint());

            for (Reference caller : callers) {
                if (caller.getReferenceType().isCall()) {
                    Function callerFunc = getFunctionContaining(caller.getFromAddress());
                    if (callerFunc == null || callerFunc.getName().equals(highFuction.getFunction().getName())) continue;

                    HighFunction callerHighFunc = decompileCallerFunction(callerFunc);
                    if (callerHighFunc != null) {
                        List<ScalarWithAddress> scalars = findScalarInCallerPcode(callerHighFunc, caller, paramIndex);
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

        private List<ScalarWithAddress> findScalarInCallerPcode(HighFunction highFunction, Reference caller, int paramIndex) {
            // call findScalarFromParameter
            List<ScalarWithAddress> scalarList = new ArrayList<>();
            Iterator<PcodeOpAST> callerPcodeOps = highFunction.getPcodeOps(caller.getFromAddress());

            while (callerPcodeOps.hasNext()) {
                PcodeOpAST pcodeOp = callerPcodeOps.next();

                if (!pcodeOp.getMnemonic().equals("CALL")) continue;
                
                if (pcodeOp.getNumInputs() > paramIndex) {
                    Varnode varParam = pcodeOp.getInput(paramIndex);

                    /* an example, where the input is constant */
                    /* (register, 0x0, 4) CALL (ram, 0x30a3620, 8) , (register, 0x0, 4) , (const, 0xb1c1fe3, 4) */
                    if (varParam.isConstant()) {
                        // Address addr = varParam.getDef().getSeqnum().getTarget();
                        scalarList.add(new ScalarWithAddress(new Scalar(varParam.getSize() * 8, varParam.getOffset()), varParam.getPCAddress()));
                    }
                    else if (varParam.isUnique() || varParam.isAddress()) {
                        // println("pcodeOp: " + pcodeOp.toString());
                        Address paramAddr = varParam.getPCAddress();
                        Instruction instr = getInstructionAt(paramAddr);

                        if (instr != null) {
                            List<ScalarWithAddress> scalars = getScalarFromInstruction(instr);
                            scalarList.addAll(scalars);
                        }
                    }
                    else {
                        /* attempt to traverse caller functions */
                        Varnode input = pcodeOp.getInput(paramIndex);
                        if (input == null || !isParameterVarnode(input)) {
                            continue;
                        }
                        int index = getPramIndexFromVarname(input);
                        scalarList.addAll(getScalarForParameter(highFunction, index));
                    }
                }
            }

            return scalarList;
        }
        
        private List<ScalarWithAddress> getScalarFromInstruction(Instruction instr) {
            List<ScalarWithAddress> scalarList = new ArrayList<>();
            Reference ref = instr.getPrimaryReference(1);

            if (ref != null) {
                Address toAddr = ref.getToAddress();
                Iterator<Data> dataIterator = this.program.getListing().getData(toAddr, true);

                while (dataIterator.hasNext()) {
                    Data data = dataIterator.next();
                    Scalar scalar = getScalarFromData(data);
                    if (scalar != null) {
                        // excluding 0xff, 0x1
                        if (scalar.getValue() < 0 || scalar.bitLength() != 32) break;
                        println("scalar: " + scalar.toString());
                        scalarList.add(new ScalarWithAddress(scalar, toAddr));
                    }
                }
            }
            
            return scalarList;
        }

        private List<ScalarWithAddress> getOperandValues(Instruction instr, int index) {
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

        private void addScalarToMap(Address addr, Scalar scalar, HashMap<Address, Set<Scalar>> map) {
            map.computeIfAbsent(addr, k -> new HashSet<>()).add(scalar);
        }

        // this implementation is not perfect, because hash value is passed by parameter. must chase the value
        // find CMP instruction, and get the value
        // if the value is located in DAT, get the value from DAT Address
        // if the value is passed by register, chase the register value
        public HashMap<Address, Set<Scalar>> analyzeInstructions(Address startAddress, Address endAddress) {
            Listing listing = this.program.getListing();
            // if start < end, then make AddressSet
            AddressSet addressSet = null;
            if (startAddress.compareTo(endAddress) <= 0){
                addressSet = new AddressSet(startAddress, endAddress);
            }
            else {
                Address minAddress = getFunctionContaining(endAddress).getBody().getMinAddress();
                Reference[] refs = getReferencesTo(minAddress);
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        if (getFunctionContaining(ref.getFromAddress()).equals(getFunctionContaining(startAddress))){
                            addressSet = new AddressSet(startAddress, ref.getFromAddress());
                        }
                    }
                }
            }
            if (addressSet == null) {
                return null;
            }
            // println(addressSet.toString());
            InstructionIterator instructions = listing.getInstructions(addressSet, true);
            HashMap<Address, Set<Scalar>> hashCandidates = new HashMap<>();
            while(instructions.hasNext()) {
                Instruction instr = instructions.next();
                Address currentAddress = instr.getMinAddress();
                int numOperands = instr.getNumOperands();
                String opCode = instr.getMnemonicString();

                if (opCode.equals("CMP")) {
                    // println("CMP: " + currentAddress.toString());
                    for (int i = 0; i < numOperands; i++){
                        // may getOperandValues return null
                        List<ScalarWithAddress> scalars = getOperandValues(instr, i);
                        if (scalars == null) continue;
                        for (ScalarWithAddress scalar : scalars) {
                            addScalarToMap(scalar.getAddress(), scalar.getScalar(), hashCandidates);
                        }
                    }
                }
            }

            return hashCandidates;
        }

        public HashMap<Address, Set<Scalar>> analyzeAllInstructions() {
            Listing listing = this.program.getListing();
            InstructionIterator instructions = listing.getInstructions(true);
            HashMap<Address, Set<Scalar>> hashCandidates = new HashMap<>();

            while (instructions.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }

                Instruction instruction = instructions.next();
                PcodeOp[] pcodeOps = instruction.getPcode();

                for (PcodeOp pcodeOp : pcodeOps) {
                    for (Varnode input : pcodeOp.getInputs()) {
                        if (input.isConstant() && input.getSize() == 4) {
                            Scalar scalar = new Scalar(input.getSize() * 8, input.getOffset());
                            addScalarToMap(instruction.getMinAddress(), scalar, hashCandidates);
                        }
                    }
                }
            }
            return hashCandidates;
        } 
    }

    public class EmulationManager {
        private EmulatorHelper emu;
        private Address startAddress;
        private Address readMemAddress;
        private Function startFunction;

        private Address endAddressOfHashing;
        private String regAtStart;
        private String regStoredHash;
        private BigInteger hash;
        private boolean timeout;

        public EmulationManager(Program program, Address readMemAddress) {
            this.emu = new EmulatorHelper(program);
            this.readMemAddress = readMemAddress;
            this.startAddress = getInstructionAt(readMemAddress).getNext().getAddress();
            this.endAddressOfHashing = null;
            this.regStoredHash = null;
            this.hash = null;
            this.timeout = false;
            this.startFunction = getFunctionContaining(readMemAddress);

            analyzeRegAtStart();
        }

        private void analyzeRegAtStart() {
            // get register at readMemAddress
            Instruction instr = getInstructionAt(this.readMemAddress);
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

        private boolean checkMatchHashCandidates(String apiName, HashMap<Address, Set<Scalar>> hashCandidates) {
            println("[*] Checking hash candidates for: " + apiName);
            boolean hashFound = false;
            String regName = null;
            // Address retAddress = getzFunctionContaining(startAddress).getBody().getMaxAddress();
            long startTime = System.nanoTime();
            Function foundFunction = null;
            Address preAddress = readMemAddress;
            
            emu.writeRegister(emu.getPCRegister(), startAddress.getOffset());
            Address stringAddress = toAddr(0xa00000);           
            emu.writeMemoryValue(stringAddress, 0x32, 0x00);
            emu.writeMemory(stringAddress, apiName.getBytes());        
            emu.writeRegister(regAtStart, stringAddress.getOffset());

            while(!monitor.isCancelled()) {
                long elapsedTime = System.nanoTime() - startTime;
                if (elapsedTime > 10000000000L) {
                    println("timeout, cannot identify range of Hashing");
                    this.timeout = true;
                    return false;
                }
                currentAddress = emu.getExecutionAddress();

                if (getInstructionAt(currentAddress).getMnemonicString().equals("RET")) {
                    if (this.startFunction.getBody().contains(currentAddress)) {
                        return false;
                    }
                    else if (hashFound) {
                        if (foundFunction.getBody().contains(currentAddress) && emu.readRegister("EAX").equals(this.hash)) {
                            this.regStoredHash = "EAX";
                            this.endAddressOfHashing = currentAddress;
                        }
                        return true;
                    }               
                }

                if (!hashFound) {
                    // println("current: " + currentAddress.toString());
                    Instruction instr = getInstructionAt(preAddress);
                    // println("now: " + instr.toString() + "@" + currentAddress.toString());
                    // int numOperands = instr.getNumOperands();
                    // for (int i=0; i<numOperands; i++) {
                        if(OperandType.isRegister(instr.getOperandType(0))) {
                            // println("now: " + instr.toString() + "@" + currentAddress.toString());
                            regName = instr.getDefaultOperandRepresentation(0);
                            if (checkHash(emu, regName, hashCandidates)) {
                                this.hash = emu.readRegister(regName);
                                println("[+] First Emulation, result equals hashCandidate: 0x" + this.hash.toString(16) + " -> address: " + currentAddress);
                                this.regStoredHash = regName;
                                println("regStoredHash: " + this.regStoredHash);
                                this.endAddressOfHashing = currentAddress;
                                foundFunction = getFunctionContaining(currentAddress);
                                // retAddress = getFunctionContaining(currentAddress).getBody().getMaxAddress();
                                hashFound = true;
                                // break;
                            }
                        }    
                    // }
                    preAddress = currentAddress;
                }
                
                // if found address is existed in start function
                if (hashFound && this.startFunction.getBody().contains(currentAddress)) return true;
                
                try {
                    emu.step(monitor);
                } catch (CancelledException e) {
                    println("Emulation step was cancelled: " + e.getMessage());
                    break;
                }
            }
            return false;
        }

        private void identifyRangeOfHashing(List<String> apiNames, HashMap<Address, Set<Scalar>> hashCandidates) {
            // long startTime = System.currentTimeMillis();
            monitor.initialize(apiNames.size());
            monitor.setMessage("Identyfing range of hashing...");
            for (String apiName : apiNames) {
                if (checkMatchHashCandidates(apiName, hashCandidates)) {
                    break;
                }
                monitor.incrementProgress();
            }
            
            // println("start: " + this.startAddress.toString());
            // println("end:"+ retAddress.toString());
            // while(!monitor.isCancelled()) {
            //     long elapsedTime = System.currentTimeMillis() - startTime;
            //     if (elapsedTime > 100000) {
            //         println("timeout, cannot identify range of Hashing");
            //         this.timeout = true;
            //         return;
            //     }
            //     currentAddress = emu.getExecutionAddress();
                
            //     if (!hashFound) {
            //         Instruction instr = getInstructionAt(currentAddress);
            //         int numOperands = instr.getNumOperands();
            //         for (int i=0; i<numOperands; i++) {
            //             if(OperandType.isRegister(instr.getOperandType(i))) {
            //                 regName = instr.getDefaultOperandRepresentation(i);
            //                 if (checkHash(emu, regName, hashCandidates)) {
            //                     this.hash = emu.readRegister(regName);
            //                     println("[+] First Emulation, result equals hashCandidate: 0x" + this.hash.toString(16) + " -> address: " + currentAddress);
            //                     this.regStoredHash = regName;
            //                     this.endAddressOfHashing = currentAddress;
            //                     retAddress = getFunctionContaining(currentAddress).getBody().getMaxAddress();
            //                     hashFound = true;
            //                     break;
            //                 }
            //             }    
            //         }
            //     }
                
            //     // println(currentAddress.toString());
            //     if (currentAddress.toString().equals(retAddress.toString())) {
            //         if (emu.readRegister("EAX").equals(this.hash)) {
            //             this.endAddressOfHashing = currentAddress;
            //         }
            //         break;
            //     }
                

            //     // if currentAddress doesn't reach to retAddress, or hash value is found, continue
            //     // if (currentAddress == retAddress && hashFound) break;
                
            //     try {
            //         emu.step(monitor);
            //     } catch (CancelledException e) {
            //         println("Emulation step was cancelled: " + e.getMessage());
            //         break;
            //     }

            // }
        }

        private BigInteger caliculateHashValue(String apiName) {
            // should set pc reg with next ins
            BigInteger hash = null;
            emu.writeRegister(emu.getPCRegister(), startAddress.getOffset());
            emu.setBreakpoint(this.endAddressOfHashing);

            Address stringAddress = toAddr(0xa00000);
            emu.writeMemoryValue(stringAddress, 0x32, 0x00);
            emu.writeMemory(stringAddress, apiName.getBytes());
            emu.writeRegister(regAtStart, stringAddress.getOffset());
            long startTime = System.nanoTime();
            while(!monitor.isCancelled()) {
                long elapsedTime = System.nanoTime() - startTime;
                if (elapsedTime > 10000000000L) {
                    println("timeout, cannot caliculate hash value for " + apiName);
                    return null;
                }

                currentAddress = emu.getExecutionAddress();

                if (emu.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT) {
                    try {
                        emu.step(monitor);
                    } catch (CancelledException e) {
                        throw new RuntimeException("Emulation step was cancelled: " + e.getMessage());
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

    public class DbiInfo {
        String start;
        List<String> addr_get_name;
        List<String> addr_get_addr;
        List<String> resolved_name;
    }

    public class DbiInfoHandler {
        private DbiInfo dynamicInfo;
        private Program currentProgram;

        public DbiInfoHandler(String dbiJsonPath, Program currentProgram) {
            this.currentProgram = currentProgram;
            this.dynamicInfo = parseDbiInfo(dbiJsonPath);
        }
    
        private DbiInfo parseDbiInfo(String dbiJsonPath) {
            Gson gson = new Gson();
            try (FileReader reader = new FileReader(dbiJsonPath)) {
                return gson.fromJson(reader, DbiInfo.class);
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
    
        public Address getReadNameAddress() {
            int entry = parseHex(dynamicInfo.start);
            int addrGetName = parseHex(dynamicInfo.addr_get_name.get(0));
            return toAddr(addrGetName - entry + currentProgram.getImageBase().getOffset());
        }
    
        public Address getReadAddrAddress() {
            int entry = parseHex(dynamicInfo.start);
            int addrGetAddr = parseHex(dynamicInfo.addr_get_addr.get(0));
            return toAddr(addrGetAddr - entry + currentProgram.getImageBase().getOffset());
        }

        public List<String> getResolvedNames() {
            return dynamicInfo.resolved_name;
        }
    
        private int parseHex(String hexString) {
            return Integer.parseInt(hexString.substring(2), 16);
        }
    }

    public class DllFunctionLoader {
        private HashMap<String, List<String>> dllFunctions;

        public DllFunctionLoader(String jsonFilePath) {
            Gson gson = new Gson();
            Type hashMapType = new TypeToken<HashMap<String, List<String>>>() {}.getType();
            try (FileReader reader = new FileReader(jsonFilePath)) {
                dllFunctions = gson.fromJson(reader, hashMapType);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public Set<String> getDllNames() {
            return dllFunctions.keySet();
        }
    
        public List<String> getFunctions(String dllName) {
            return dllFunctions.get(dllName);
        }
    
        public HashMap<String, List<String>> getAllDllFunctions() {
            return dllFunctions;
        }

        public int getTotalFunctionCount() {
            int count = 0;
            for (String dll : dllFunctions.keySet()) {
                count += dllFunctions.get(dll).size();
            }
            return count;
        }
    }

    InstructionAnalyzer insAnalyzer;

    @Override
    protected void run() throws Exception {
        String currentPath = getSourceFile().getParentFile().getParentFile().getAbsolutePath();
        
        // String separator= null;
        // this is not perfect
        // if (currentPath.contains("\\")) separator = "\\";
        // if (currentPath.contains("/")) separator = "/";
        // if (separator == null) {
        //     throw new RuntimeException("misterious OS");
        // }
        String separator = System.getProperty("os.name").toLowerCase().contains("win") ? "\\" : "/";

        /* setup env from DBI information */
        String fileName = getProgramFile().getName();
        if (fileName.endsWith(".exe")) {
            fileName = fileName.substring(0, fileName.length() - 4);
        }
        String dbiJsonPath = currentPath + separator + "out" + separator + "dbi" + separator + fileName + ".json";
        DbiInfoHandler handler = new DbiInfoHandler(dbiJsonPath, currentProgram);
        Address readNameAddress = handler.getReadNameAddress();
        Address readAddrAddress = handler.getReadAddrAddress();
        List<String> resolvedNames = handler.getResolvedNames();
        println("[+] readNameAddress: " + readNameAddress.toString());
        println("[+] readAddrAddress: " + readAddrAddress.toString());
        
        /* search hash candidates */   
        hashvaluesAnalyzer hashAnalyzer = new hashvaluesAnalyzer(currentProgram);
        HashMap<Address, Set<Scalar>> hashCandidates = hashAnalyzer.analyzeInstructions(readNameAddress, readAddrAddress);
        if (hashCandidates.isEmpty()) {
            hashCandidates = hashAnalyzer.analyzeAllInstructions();
            if (hashCandidates.isEmpty()) throw new RuntimeException("No hash candidates found.");
        }

        List<String> candidates = new ArrayList<String>();
        for (Address addr : hashCandidates.keySet()) {
            for (Scalar scalar : hashCandidates.get(addr)) {
                candidates.add(scalar.toString(16, false, false, "0x", ""));
            }
        }
        println("[+] hashCandidates: " + Arrays.toString(candidates.toArray()));

        /* analyze memory-access instruction */
        insAnalyzer = new InstructionAnalyzer(this);
        // InstructionAnalyzer analyzer = new InstructionAnalyzer();
        String dstRegisterAtStart = insAnalyzer.getRegister(readNameAddress, 0);
        // if dstRegister is null, then the program will be cancelled
        if (dstRegisterAtStart == null) {
            throw new RuntimeException("register is null?");
        }

        /* identify ranges of Hashing by step emulating */
        EmulationManager emuManager = new EmulationManager(currentProgram, readNameAddress);
        emuManager.identifyRangeOfHashing(resolvedNames, hashCandidates);
        // if (emuManager.timeout) {
        //     throw new RuntimeException("cannot find Hashing, so stopped...");
            
        // }    
        if (emuManager.endAddressOfHashing == null) {
            throw new RuntimeException("cannot find end of Hashing");
        }
        println("[+] end of hashing: " + emuManager.endAddressOfHashing.toString());

        /* parse APInames db(json) */
        String dllJsonPath = currentPath + separator + "dlls" + separator + "exports.json";
        DllFunctionLoader loader = new DllFunctionLoader(dllJsonPath);
        
        /* caliculate hashDB */
        println("[+] now caliculating hash values...");
        HashMap<String, BigInteger> hashDB = new HashMap<>();
        Set<String> dllNames = loader.getDllNames();
        monitor.initialize(loader.getTotalFunctionCount());
        monitor.setMessage("Creating DB ...");
        for (String dll: dllNames) {
            if (monitor.isCancelled()) {
                break;
            }

            for (String api: loader.getFunctions(dll)) {
                BigInteger hash = emuManager.caliculateHashValue(api);
                if (hash != null) hashDB.put(api, hash);
                else println("[!] hash of "+ api + "cannot be caliculated...");
                // println("[+] API: " + api + " -> hash: 0x" + hash.toString(16));
                monitor.incrementProgress();            
            }

        }
        String dbPath = currentPath + separator + "out" + separator + "db" + separator + fileName + ".json";
        Path dbOutputPath = Paths.get(dbPath);
        writeHashDatabase(hashDB, dbOutputPath);
        println("[+] caliculation done! output to: " + dbOutputPath.toAbsolutePath());

        /* search hash value in DB and resolve API name */
        println("[+] now resolving API names from hash values...");
        String resultsPath = currentPath + separator + "out" + separator + "resolve" + separator + fileName + ".txt";
        searchHashValues(hashDB, hashCandidates, resultsPath);

    }

    public boolean checkHash(EmulatorHelper emu, String reg, HashMap<Address, Set<Scalar>> candidates) {
        BigInteger result = emu.readRegister(reg);
        for (Address addr : candidates.keySet()) {
            for (Scalar scalar : candidates.get(addr)) {
                // long to BigInteger
                BigInteger hashValue = BigInteger.valueOf(scalar.getUnsignedValue());
                // println("result: " + result.toString(16) + " -> " + hashValue.toString(16) + "@" + emu.getExecutionAddress());
                if (result.equals(hashValue)) {
                    // println("match! " + result.toString(16) + " -> " + hashValue.toString(16));
                    return true;
                }
            }
        }

        return false;
    }

    public void searchHashValues(HashMap<String, BigInteger> hashDB, HashMap<Address, Set<Scalar>> hashCandidates, String outputFilePath) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
            for (Address addr : hashCandidates.keySet()) {
                Set<Scalar> scalars = hashCandidates.get(addr);
                for (Scalar scalar : scalars) {
                    BigInteger scalarValue = BigInteger.valueOf(scalar.getUnsignedValue());
                    writeMatchingAPIs(hashDB, addr, scalarValue, writer);
                }
            }
            println("[*] Resolved results written to file: " + outputFilePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeMatchingAPIs(HashMap<String, BigInteger> hashDB, Address addr, BigInteger scalarValue, BufferedWriter writer) throws IOException {
        for (String api : hashDB.keySet()) {
            BigInteger hashValue = hashDB.get(api);
            if (!hashValue.equals(scalarValue)) {
                continue;
            }
            String output = "[+] API: " + api + " -> hash: 0x" + hashValue.toString(16) + " -> Address: " + addr;
            println(output);
            writer.write(output + "\n");
        }
    }



    public void writeHashDatabase(HashMap<String, BigInteger> hashDB, Path filePath) {
        Gson gson = new GsonBuilder()
            .registerTypeAdapter(BigInteger.class, new JsonSerializer<BigInteger>() {
                @Override
                public JsonElement serialize(BigInteger src, Type typeOfSrc, JsonSerializationContext context) {
                    return new JsonPrimitive("0x" + src.toString(16));
                }
            })
            .setPrettyPrinting()
            .create();
        String json = gson.toJson(hashDB);

        try {
            Files.writeString(filePath, json, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            println("[*] HashDB written to: " + filePath.toAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}