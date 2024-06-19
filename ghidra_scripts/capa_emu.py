from ghidra.app.emulator import EmulatorHelper
from ghidra.app.script import GhidraScript
from ghidra.app.util.opinion import PeLoader
from ghidra.pcode.emulate import EmulateExecutionState
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction
from ghidra.program.model.symbol import Reference, Symbol, SymbolUtilities
from ghidra.program.database import ProgramDB

import logging
import pathlib
import capa
import capa.main
import capa.rules
import capa.ghidra.helpers
import capa.render.default
import capa.capabilities.common
import capa.features.extractors.ghidra.extractor
import capa.features.freeze as frz


class ResolvingGhidra():
    def __init__(self):
        self.emuHelper = None
        self.hashCall = None
        self.hashReturn = None
        self.registry_size = None
        self.program = currentProgram()

    def getNumberOfFunctionsAddrs(self, capabilities) -> set:
        # loop all capabilities address
        for capability in capabilities["resolve function by parsing PE exports"]:
            # address to Ghidra Address
            print(f"Function parsing the PE header : {toAddr(frz.Address.from_capa(capability[0]).value)}")
            for match in capability[1].children:
                # extract And features
                if isinstance(match.statement, capa.engine.And):
                    # extract 3 or more [offset, or , some]
                    for c in match.children:
                        # extract some
                        if isinstance(c.statement, capa.engine.Some):
                            # extract ImageExportDirectory sturecture       
                            for imageExportDirectory in c.children:
                                # extract number of functions
                                if imageExportDirectory.statement.value == 0x14:
                                    return imageExportDirectory.locations
                                
    def findNumberOfFunctions(self):
        logger = logging.getLogger("ResolvingGhidra")
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)
        # path to capa rules
        rules_path: pathlib.Path = pathlib.Path("path to capa rules")
        logger.info("running capa using rules from %s", str(rules_path))

        rules = capa.main.get_rules([rules_path])

        meta = capa.ghidra.helpers.collect_metadata([rules_path])
        
        extractor = capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()

        capabilities, counts = capa.capabilities.common.find_capabilities(rules, extractor, True)
        
        meta.analysis.feature_counts = counts["feature_counts"]
        meta.analysis.library_functions = counts["library_functions"]
        meta.analysis.layout = capa.main.compute_layout(rules, extractor, capabilities)
        
        if capa.capabilities.common.has_file_limitation(rules, capabilities, is_standalone=False):
            logger.info("capa encountered warnings during analysis")
        
        numberOfFuctionsAddrs = [toAddr(hex(addr)) for addr in self.getNumberOfFunctionsAddrs(capabilities)]

        return numberOfFuctionsAddrs

    def findCallInstruction(self, startAddr):
        codeUnitIterator = self.program.getListing().getCodeUnits(startAddr, True)
        while (codeUnitIterator.hasNext() and not monitor().isCancelled()):
            codeUnit = codeUnitIterator.next()
            if (codeUnit.getMnemonicString() == "CALL"):
                return codeUnit.getAddress()
        return None
    
    def run(self):
        # find numberofFunctions
        numberOfFuctionsAddrs = self.findNumberOfFunctions()
        numberOfFuctionsAddr = numberOfFuctionsAddrs[0]
        print(f"[search] ImageExportDirectory.NumberOfFunctions : {numberOfFuctionsAddr}")
        # addr = toAddr(0x401113)
        addr = numberOfFuctionsAddr
        hashCallAddr = self.findCallInstruction(addr)
        if hashCallAddr is None:
            printerr("Instruction not found at call site for: Hash Function\n")
            return
        print(f"[search] Hash Func Call Site : {hashCallAddr}")

        self.hashCall = getInstructionAt(hashCallAddr)

        self.pushEdx = self.hashCall.getPrevious().getAddress()
        if getInstructionAt(self.pushEdx).getMnemonicString() != "PUSH":
            printerr("Instruction not found at push edx\n")
            return

        self.hashReturn = self.hashCall.getFallThrough()
        # print("Hash Return: " + str(self.hashReturn))
        
        # too many api_names in kernel32.dll
        import json
        # JSONファイルを開く
        with open('../dlls/dll.json', 'r') as f:
            data = json.load(f)

        # dll_nameをキーとしてapi_namesのリストを取得
        api_names = data['kernel32.dll']

        # Establish emulation helper
        self.emuHelper = EmulatorHelper(self.program)
        try:
            for api_name in api_names:
                # Setup stack pointer
                self.registry_size = self.emuHelper.getStackPointerRegister().getBitLength()
                stack_offset = ((1 << (self.registry_size - 1)) - 1) ^ ((1 << (self.registry_size // 2)) - 1)
                self.emuHelper.writeRegister(self.emuHelper.getStackPointerRegister(), stack_offset)

                # Setup breakpoints
                self.emuHelper.setBreakpoint(self.hashReturn)

                string_address = toAddr(0xa00000)
                # initialize memory at string_address
                self.emuHelper.writeMemoryValue(string_address, 0x32, 0x00)
        
                self.emuHelper.writeMemory(string_address, api_name.encode())

                # todo : identify register used to store string address
                # write EDX to string_address
                self.emuHelper.writeRegister("EDX", string_address.getOffset())

                self.emuHelper.writeRegister(self.emuHelper.getPCRegister(), self.pushEdx.getOffset())

                # Execution loop until return from function or error occurs
                while not monitor().isCancelled():
                    emu_success = False
                    if self.emuHelper.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT:
                        emu_success = self.emuHelper.step(monitor())
                    else:
                        # print("breakpoint hit")
                        self.process_breakpoint(self.emuHelper.getExecutionAddress())
                        # break
                        self.emuHelper.dispose()
                        break

                    if monitor().isCancelled():
                        print("Emulation cancelled")
                        return
                    if not emu_success:
                        last_error = self.emuHelper.getLastError()
                        printerr("Emulation Error: " + last_error)
                        return
        finally:
            # cleanup resources and release hold on currentProgram
            self.emuHelper.dispose()

    def process_breakpoint(self, addr):
        # print("process_breakpoint")
        # print("addr : " + str(addr))
        if addr == self.hashReturn:
            return_value = self.emuHelper.readRegister("EAX")
            # return_value is hash value embedded in the binary
            if return_value == 0x8df92f7b:
                print(f"[emulation] hash value : {hex(return_value)}")
                mem = self.emuHelper.readMemory(toAddr(0xa00000), self.registry_size)
                mem_str = "".join(chr(m) for m in mem)
                print(f"[emulation] Resolved API Name : {mem_str}")

# Create an instance of the script and run it
script = ResolvingGhidra()
script.run()