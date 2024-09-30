//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.util.List;

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
import jnr.ffi.types.off_t;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.flatapi.FlatProgramAPI;

public class emulate_by_step_observation extends GhidraScript {

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

        // public boolean isRegister(Address address) {
        //     Instruction instr = getInstructionAt(address);
        //     if (instr == null) {
        //         throw new RuntimeException("No instruction at the specified address.");
        //     }
        //     int operandIndex = 0;
        // }


    }


    @Override
    protected void run() throws Exception {

        /* setup env from DBI information */
        Address startAddress = toAddr(0x40131e);
        // Address startAddress = toAddr(0x401342);
        // below is conti
        // Address startAddress = toAddr(0x4033f2);        

        Address endAddress = toAddr(0x401349);
        // below is conti
        // Address endAddress = toAddr(0x403413);
        
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
        String apiName = "CreateThreadg";
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

        //     else if ((instr.getOperandType(0) & OperandType.DYNAMIC) != 0) {
        //         // printMem(emu);
        //         /* read stack address and read bytes from memory */
        //         Varnode[] inputs = instr.getPcode()[0].getInputs();
        //         for (Varnode input: inputs) {
        //             println("input: " + input.toString());
        //             if (input.)
        //         }

        //    }
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
