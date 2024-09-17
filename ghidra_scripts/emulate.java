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
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.flatapi.FlatProgramAPI;

public class emulate extends GhidraScript {

    public void run() throws Exception {

        /* setup env from DBI information */
        // Address startAddress = toAddr(0x40131e);
        // conti
        Address startAddress = toAddr(0x4033f2);        
        // Address endAddress = toAddr(0x401349);
        // conti
        Address endAddress = toAddr(0x403413);
        
        /* analyze memory-access instruction */
        String startRegister = getRegister(startAddress);
        if (startRegister == null) {
            throw new RuntimeException("register is null?");
        }
        else {
            println("reg: " + startRegister + " at: " + startAddress.toString());
        }

        /* setup emulation helper */
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        emu.setBreakpoint(endAddress);
        // initialize memory at stringAddress
        Address stringAddress = toAddr(0xa00000);
        emu.writeMemoryValue(stringAddress, 0x32, 0x00);
        // emu.writeMemory(stringAddress, "CreateThread".getBytes());
        emu.writeMemory(stringAddress, "LoadLibraryA".getBytes());
        
        emu.writeRegister(startRegister, stringAddress.getOffset());
        emu.writeRegister(emu.getPCRegister(), startAddress.getOffset());
        
        while(!monitor.isCancelled()){
            println("pc: 0x" + emu.readRegister(emu.getPCRegister()).toString(16));
            printReg(emu);
            if (emu.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT){
                emu.step(monitor);
            }
            else {
                break;
            }
        }
    
    }

    public String getRegister(Address startAddress) {
        Instruction instr = getInstructionAt(startAddress);
    
        if (instr == null) {
            throw new RuntimeException("No instruction at the specified address.");
        }

        // 第一オペランドを取得
        int operandIndex = 0; // 第一オペランド
        String operandValue = null;
        if (instr.getNumOperands() > operandIndex) {
            int operandType = instr.getOperandType(operandIndex);
            operandValue = instr.getDefaultOperandRepresentation(operandIndex);
            // println("First operand: " + operandValue + " (type: " + operandType + ")");
            // オペランドタイプを判別
            // println("operandType: " + operandType);
            // println("register AND" + (operandType & OperandType.REGISTER));
            if ((operandType & OperandType.REGISTER) != 0) {
                println("The first operand is a register: " + operandValue);
            } else if ((operandType & OperandType.DYNAMIC) != 0) {
                println("The first operand is dynamic: " + operandValue);
            } else {
                println("The first operand is of another type: " + operandValue + ", type: " + operandType);
            }
        } else {
            println("The instruction does not have a first operand.");
        }

        return operandValue;

        // if (operandValue != null) {
        //     switch(operandValue){
        //         case "EDX":
        //             println("in EDX case");
        //             // emuHelper.writeRegister(operandValue, 0x12345678);
        //             // println("EDX: " + emuHelper.readRegister(operandValue).toString(16));
        //             break;
        //         default:
        //             println("Not implemeted");
        //             break;
        //     }
        // }
    }

    public void printReg(EmulatorHelper emu) {
        List <Register> programRegisters = currentProgram.getProgramContext().getRegisters();
        for (Register reg: programRegisters) {
            // hidden registers are like PC, SP, etc.
            if (!reg.isHidden()) {
                // if reg is eax or ebx
                if (reg.getName().equals("EAX")){
                    println(reg.getName() + ": 0x" + emu.readRegister(reg).toString(16));
                }
            }
        }
    }

    

}
