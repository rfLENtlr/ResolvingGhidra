import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.flatapi.FlatProgramAPI;


public class InstructionAnalyzer{
    private FlatProgramAPI f;

    public InstructionAnalyzer(FlatProgramAPI f){
        this.f = f;
    }

    public String getRegister(Address address, int operandIndex) {
        Instruction instr = f.getInstructionAt(address);
        if (instr == null) {
            throw new RuntimeException("No instruction at the specified address.");
        }

        String registerName = null;
        if (instr.getNumOperands() > operandIndex) {
            registerName = instr.getDefaultOperandRepresentation(operandIndex);
        } else {
            return null;
        }
        return registerName;
    }
}
