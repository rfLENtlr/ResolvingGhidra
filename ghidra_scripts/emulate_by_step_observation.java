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
import java.util.Iterator;
import java.util.Set;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.lang.reflect.Type;

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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;


public class emulate_by_step_observation extends GhidraScript {

    public static int x86 = 8;

    public class InstructionAnalyzer {

        public String getRegister(Address address, int operandIndex) {
            Instruction instr = getInstructionAt(address);
            if (instr == null) {
                throw new RuntimeException("No instruction at the specified address.");
            }
            // get first operand
            // int operandIndex = 0;
            String registerName = null;
            if (instr.getNumOperands() > operandIndex) {
                registerName = instr.getDefaultOperandRepresentation(operandIndex);
            } else {
                println("The instruction does not have a first operand.");
            }
            return registerName;
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

        private List<Scalar> handleScalarOperand(Instruction instr, int index) {
            List<Scalar> scalarList = new ArrayList<>();
            Scalar scalar = instr.getScalar(index);
            if (scalar != null) {
                if (scalar.getValue() > 0)
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
                    if (scalar.getValue() > 0)
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

                while (dataIterator.hasNext()) {
                    Data data = dataIterator.next();
                    Scalar scalar = getScalarFromData(data);
                    if (scalar != null) {
                        if (scalar.getValue() == 0) break;
                        if (scalar.getValue() > 0)
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
            while(instructions.hasNext()) {
                Instruction instr = instructions.next();
                Address currentAddress = instr.getMinAddress();
                int numOperands = instr.getNumOperands();
                String opCode = instr.getMnemonicString();

                if (opCode.equals("CMP")) {
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

            return hashCandidates;
        }
    }

    public class EmulationManager {
        private EmulatorHelper emu;
        private Address startAddress;
        private Address readMemAddress;
        private Address endAddressOfHashing;
        private String regAtStart;
        private String regStoredHash;

        public EmulationManager(Program program, Address readMemAddress) {
            this.emu = new EmulatorHelper(program);
            this.readMemAddress = readMemAddress;
            this.startAddress = getInstructionAt(readMemAddress).getNext().getAddress();
            this.endAddressOfHashing = null;
            this.regStoredHash = null;

            analyzeRegAtStart();
            emu.writeRegister(emu.getPCRegister(), startAddress.getOffset());
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

        private void identifyRangeOfHashing(String apiName, HashMap<Address, List<Scalar>> hashCandidates) {
            Address retAddress = getFunctionContaining(startAddress).getBody().getMaxAddress();
            Address stringAddress = toAddr(0xa00000);
            emu.writeMemoryValue(stringAddress, 0x32, 0x00);
            emu.writeMemory(stringAddress, apiName.getBytes());        
            emu.writeRegister(regAtStart, stringAddress.getOffset());


            String regName = null;
            boolean hashFound = false;
            while(!monitor.isCancelled()) {
                currentAddress = emu.getExecutionAddress();
                Instruction instr = getInstructionAt(currentAddress);
                int numOperands = instr.getNumOperands();
                for (int i=0; i<numOperands; i++) {
                    if(OperandType.isRegister(instr.getOperandType(i))) {
                        regName = instr.getDefaultOperandRepresentation(i);
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
            // should set pc reg with next ins
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

        public String getResolvedName() {
            return dynamicInfo.resolved_name.get(0);
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
    }

    @Override
    protected void run() throws Exception {
        /* setup env from DBI information */
        String dbiJsonPath = getSourceFile().getParentFile().getParentFile().getAbsolutePath() + "\\out\\output.json";
        DbiInfoHandler handler = new DbiInfoHandler(dbiJsonPath, currentProgram);
        Address readNameAddress = handler.getReadNameAddress();
        Address readAddrAddress = handler.getReadAddrAddress();
        String resolvedName = handler.getResolvedName();
        
        /* search hash candidates */
        hashvaluesAnalyzer hashAnalyzer = new hashvaluesAnalyzer(currentProgram);
        HashMap<Address, List<Scalar>> hashCandidates = hashAnalyzer.analyzeInstructions(readNameAddress, readAddrAddress);
        List<String> candidates = new ArrayList<String>();
        for (Address addr : hashCandidates.keySet()) {
            for (Scalar scalar : hashCandidates.get(addr)) {
                candidates.add(scalar.toString());
            }
        }
        println("[+] hashCandidates: " + Arrays.toString(candidates.toArray()));


        /* analyze memory-access instruction */
        InstructionAnalyzer analyzer = new InstructionAnalyzer();
        String dstRegisterAtStart = analyzer.getRegister(readNameAddress, 0);
        // if dstRegister is null, then the program will be cancelled
        if (dstRegisterAtStart == null) {
            throw new RuntimeException("register is null?");
        }

        /* identify ranges of Hashing by step emulating */
        EmulationManager emuManager = new EmulationManager(currentProgram, readNameAddress);
        emuManager.identifyRangeOfHashing(resolvedName, hashCandidates);

        /* parse APInames db(json) */
        String dir = getSourceFile().getParentFile().getParentFile().getAbsolutePath();
        String dllJsonPath = dir + "\\dlls\\exports.json"; // windows
        // String dllJsonPath = dir + "/dlls/exports.json"; // linux
        DllFunctionLoader loader = new DllFunctionLoader(dllJsonPath);
        
        /* caliculate hashDB */
        println("[+] now caliculating hash values...");
        HashMap<String, BigInteger> hashDB = new HashMap<>();
        for (String dll: loader.getDllNames()) {
            for (String api: loader.getFunctions(dll)) {
                BigInteger hash = emuManager.caliculateHashValue(api);
                hashDB.put(api, hash);
            }
        }
        println("[+] caliculation done!");

        /* search hash value in DB and resolve API name */
        println("[+] now resolving API names from hash values...");
        searchHashValues(hashDB, hashCandidates);

    }

    public boolean checkHash(EmulatorHelper emu, String reg, HashMap<Address, List<Scalar>> candidates) {
        BigInteger result = emu.readRegister(reg);
        for (Address addr : candidates.keySet()) {
            for (Scalar scalar : candidates.get(addr)) {
                // long to BigInteger
                BigInteger hashValue = BigInteger.valueOf(scalar.getValue());
                if (result.equals(hashValue)) {
                    return true;
                }
            }
        }

        return false;
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