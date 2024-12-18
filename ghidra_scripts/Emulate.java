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
                // if (scalar.getValue() > 0)
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
            String varName = var.getHigh().getName();
            // println("varName: " + varName);
            return varName.startsWith("param");
        }

        private int getPramIndexFromVarname(Varnode var) {
            String varName = var.getHigh().getName();
            return Integer.parseInt(varName.substring(6));
        }

        /* try to extract an argument from caller functions */
        private List<Scalar> getScalarForParameter(HighFunction highFuction, int paramIndex) {
            List<Scalar> scalarList = new ArrayList<>();
            Reference[] callers = getReferencesTo(highFuction.getFunction().getEntryPoint());

            for (Reference caller : callers) {
                if (caller.getReferenceType().isCall()) {
                    Function callerFunc = getFunctionContaining(caller.getFromAddress());
                    if (callerFunc == null || callerFunc.getName().equals(highFuction.getFunction().getName())) continue;

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

                    /* an example, where the input is constant */
                    /* (register, 0x0, 4) CALL (ram, 0x30a3620, 8) , (register, 0x0, 4) , (const, 0xb1c1fe3, 4) */
                    if (varParam.isConstant()) scalarList.add(new Scalar(varParam.getSize() * 8, varParam.getOffset()));
                    else if (varParam.isUnique() || varParam.isAddress()) {
                        // println("pcodeOp: " + pcodeOp.toString());
                        Address paramAddr = varParam.getPCAddress();
                        Instruction instr = getInstructionAt(paramAddr);

                        if (instr != null) {
                            List<Scalar> scalars = getScalarFromInstruction(instr);
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
                        // if (scalar.getValue() > 0)
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
                    // println("CMP: " + currentAddress.toString());
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

        private boolean checkMatchHashCandidates(String apiName, HashMap<Address, List<Scalar>> hashCandidates) {
            boolean hashFound = false;
            String regName = null;
            Address retAddress = getFunctionContaining(startAddress).getBody().getMaxAddress();
            long startTime = System.currentTimeMillis();
            
            emu.writeRegister(emu.getPCRegister(), startAddress.getOffset());
            Address stringAddress = toAddr(0xa00000);           
            emu.writeMemoryValue(stringAddress, 0x32, 0x00);
            emu.writeMemory(stringAddress, apiName.getBytes());        
            emu.writeRegister(regAtStart, stringAddress.getOffset());
            
            while(!monitor.isCancelled()) {
                long elapsedTime = System.currentTimeMillis() - startTime;
                if (elapsedTime > 10000) {
                    println("timeout, cannot identify range of Hashing");
                    this.timeout = true;
                    return false;
                }
                currentAddress = emu.getExecutionAddress();
                if (!hashFound) {
                    // println("current: " + currentAddress.toString());
                    Instruction instr = getInstructionAt(currentAddress);
                    int numOperands = instr.getNumOperands();
                    for (int i=0; i<numOperands; i++) {
                        if(OperandType.isRegister(instr.getOperandType(i))) {
                            regName = instr.getDefaultOperandRepresentation(i);
                            if (checkHash(emu, regName, hashCandidates)) {
                                this.hash = emu.readRegister(regName);
                                println("[+] First Emulation, result equals hashCandidate: 0x" + this.hash.toString(16) + " -> address: " + currentAddress);
                                this.regStoredHash = regName;
                                this.endAddressOfHashing = currentAddress;
                                retAddress = getFunctionContaining(currentAddress).getBody().getMaxAddress();
                                hashFound = true;
                                break;
                            }
                        }    
                    }
                }

                if (hashFound && this.startFunction.getBody().contains(currentAddress)) return true;

                // If hashFound is true, execute until retAddress and check if EAX matches the hash.
                // If hashFound is false and retAddress is reached, it means the hash was not found, so exit.
                if (currentAddress.toString().equals(retAddress.toString())) {
                    if (hashFound) {
                        if (emu.readRegister("EAX").equals(this.hash)) {
                            this.endAddressOfHashing = currentAddress;
                        }
                        return true;
                    }
                    return false;
                }
                
                try {
                    emu.step(monitor);
                } catch (CancelledException e) {
                    println("Emulation step was cancelled: " + e.getMessage());
                    break;
                }
            }
            return false;
        }

        private void identifyRangeOfHashing(List<String> apiNames, HashMap<Address, List<Scalar>> hashCandidates) {
            // long startTime = System.currentTimeMillis();
            for (String apiName : apiNames) {
                if (checkMatchHashCandidates(apiName, hashCandidates)) {
                    break;
                }
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

            while(!monitor.isCancelled()) {
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
        HashMap<Address, List<Scalar>> hashCandidates = hashAnalyzer.analyzeInstructions(readNameAddress, readAddrAddress);
        if (hashCandidates.isEmpty()) {
            throw new RuntimeException("No hash candidates found.");
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
        for (String dll: loader.getDllNames()) {
            for (String api: loader.getFunctions(dll)) {
                BigInteger hash = emuManager.caliculateHashValue(api);
                hashDB.put(api, hash);
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

    public void searchHashValues(HashMap<String, BigInteger> hashDB, HashMap<Address, List<Scalar>> hashCandidates, String outputFilePath) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
            for (Address addr : hashCandidates.keySet()) {
                List<Scalar> scalars = hashCandidates.get(addr);
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