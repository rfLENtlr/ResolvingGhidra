//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.util.List;
import java.util.Objects;
import java.util.HashMap;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.sleigh.grammar.SleighEcho.endian_return;
import ghidra.sleigh.grammar.SleighParser.oplist_return;
import ghidra.sleigh.grammar.SleighParser_SemanticParser.return_stmt_return;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.flatapi.FlatProgramAPI;


public class emulate_by_step_observation extends GhidraScript {

    public static int x86 = 8;

    public class EmulationManager {
        private EmulatorHelper emu;
        private Address startAddress;
        private Address endAddress;

        public EmulationManager(Program program, Address startAddress, Address endAddress) {
            this.emu = new EmulatorHelper(program);
            this.startAddress = startAddress;
            this.endAddress = endAddress;
        }

    }

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
                if ((operandType & OperandType.REGISTER) != 0) {
                    println("The first operand is a register: " + registerName);
                } else if ((operandType & OperandType.DYNAMIC) != 0) {
                    println("The first operand is dynamic: " + registerName);
                } else {
                    println("The first operand is of another type: " + registerName + ", type: " + operandType);
                }
            } else {
                println("The instruction does not have a first operand.");
            }
            return registerName;
        } 
    }

    public class hashvaluesAnalyzer {
        private Program program;
        private HashMap<Address, Long> hashValues = new HashMap<>();

        public hashvaluesAnalyzer(Program program) {
            this.program = program;
        }

        public HashMap<Scalar, Address> analyzeAllInstructions() {
            HashMap<Scalar, Address> hashVaules = new HashMap<>();

            Listing listing = this.program.getListing();
            InstructionIterator instructions = listing.getInstructions(true);

            while (instructions.hasNext()){
                Instruction instr = instructions.next();
                int opCount = instr.getNumOperands();
                Address currentAddress = instr.getAddress();
                // if (instr.getAddress().toString().equals("00401345")){    
                
                // println("[+] current: " + instr.getAddress().toString());

                for (int i = 0; i < opCount; i++) {
                    int opType = instr.getOperandType(i);
                    if (OperandType.isScalar(opType)) {
                        Scalar scalar = instr.getScalar(i);
                        if (scalar.toString().length() == 10) {
                            // println("scalar: " + scalar.toString());
                            hashVaules.put(scalar, currentAddress);
                        }
                        // println("scalar: " + scalar.toString());
                    } else if (OperandType.isDataReference(opType)) {
                        Reference ref = instr.getPrimaryReference(i);
                        if (ref.isMemoryReference()) {
                            Address toAddr = ref.getToAddress();
                            Data data = listing.getDefinedDataAt(toAddr);
                            if (data != null && data.getValue() != null) {
                                Object value = data.getValue();
                                if (value instanceof Scalar) {
                                    Scalar dat_value = (Scalar) value;
                                    if (dat_value.toString().length() == 10) {
                                        // println("data scalar: " + dat_value.toString());
                                        hashVaules.put(dat_value, currentAddress);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return hashVaules;
        }
        // this implementation is not perfect, because hash value is passed by parameter. must chase the value
        public void analyzeInstructions(Address startAddress, Address endAddress) {
            Listing listing = this.program.getListing();
            AddressSetView addressSet = new AddressSet(startAddress, endAddress);
            InstructionIterator instructions = listing.getInstructions(addressSet, true);
            // 関数呼び出しやJMP先には対応していない
            // check operand, and if it is scalar, get the value, and if it is DAT , refer to and get the value
            while(instructions.hasNext()) {
                Instruction instr = instructions.next();
                Address currentAddress = instr.getAddress();
                println("current: " + currentAddress.toString());
                int numOperands = instr.getNumOperands();
                for (int i = 0; i < numOperands; i++) {
                    int operandType = instr.getOperandType(i);
                    if (OperandType.isScalar(operandType)) {
                        Scalar scalar = instr.getScalar(i);
                        println("scalar: " + scalar.toString());
                        hashValues.put(currentAddress, scalar.getValue());
                    } else if (OperandType.isDataReference(operandType)) {
                        println("data");
                        Reference ref = instr.getPrimaryReference(i);
                        if (ref.isMemoryReference()) {
                            // get values from memory
                            Address toAddr = ref.getToAddress();
                            println("toAddr: " + toAddr.toString());
                            Data data = listing.getDefinedDataAt(toAddr);
                            if (data != null) {
                                println("data scalar: " + data.getValue().toString());
                            }
                        }
                    } else {
                        // 512: register such as EDX
                        // 4194304(DYNAMIC): dword ptr [ECX + EAX*0x4]
                        // 4202496(): dword ptr [EBP + local_14]
                        println("operand type: " + Integer.toHexString(operandType));
                    }
                }
            }


        }

        
    }


    @Override
    protected void run() throws Exception {

        /* setup env from DBI information */
        // Address startAddress = toAddr(0x40131e);
        // Address startAddress = toAddr(0x401342);
        // below is conti
        Address startAddress = toAddr(0x4033f2);        

        // Address endAddress = toAddr(0x401349);
        // Address endAddress = toAddr(0x401353);
        // below is conti
        Address endAddress = toAddr(0x403413);
        hashvaluesAnalyzer hashAnalyzer = new hashvaluesAnalyzer(currentProgram);
        // hashAnalyzer.analyzeInstructions(startAddress, endAddress);
        HashMap<Scalar, Address> hashValues = hashAnalyzer.analyzeAllInstructions();

        for (Scalar scalar : hashValues.keySet()) {
            println("hash_candidate: " + scalar+ " -> Address: " + hashValues.get(scalar));
        }

        if (true) {
            throw new RuntimeException("end");
        }
        

        /* analyze memory-access instruction */
        InstructionAnalyzer analyzer = new InstructionAnalyzer(currentProgram);
        String dstRegisterAtStart = analyzer.getRegister(startAddress, 0);
        // String startRegister = getRegister(startAddress);
        if (dstRegisterAtStart == null) {
            throw new RuntimeException("register is null?");
        }
        else {
            println("reg: " + dstRegisterAtStart + " at: " + startAddress.toString());
        }

        /* setup emulation helper */
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        String apiName = "CreateThread";
        emu.setBreakpoint(endAddress);
        // initialize memory at stringAddress
        Address stringAddress = toAddr(0xa00000);
        emu.writeMemoryValue(stringAddress, 0x32, 0x00);
        // emu.writeMemory(stringAddress, "CreateThread".getBytes());
        emu.writeMemory(stringAddress, apiName.getBytes());        
        emu.writeRegister(dstRegisterAtStart, stringAddress.getOffset());
        emu.writeRegister(emu.getPCRegister(), startAddress.getOffset());
        
        String firstReg = null;
        String secondReg = null;
        while(!monitor.isCancelled()){
            currentAddress = emu.getExecutionAddress();
            firstReg = analyzer.getRegister(currentAddress, 0);
            Instruction instr = getInstructionAt(currentAddress);
            // if first operand is register
            println("current: " + currentAddress.toString());
            if((instr.getOperandType(0) & OperandType.REGISTER) != 0) {
                printReg(emu, firstReg);
            }
            if((instr.getOperandType(1) & OperandType.REGISTER) != 0) {
                secondReg = analyzer.getRegister(currentAddress, 1);
                printReg(emu, secondReg);
            }

            if (emu.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT){
                emu.step(monitor);
            }
            else {
                break;
            }
        }
    
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
    

}
