// TODO: print to file instead of console
#define _CRT_SECURE_NO_WARNINGS
#define MAX_ENTRIES 1000
#define MAX_PATH_LENGTH 260
#define OUTPUT_FILE "..\\out\\output.json"

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"

#include "itree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

module_data_t *main_mod;            // Store infor about main module (e.g. analyzed malware sample)
itreenode_t *intervalTree = NULL;   // Root node for the interval tree

DWORD addr_name_array[MAX_ENTRIES];
DWORD addr_address_array[MAX_ENTRIES];
char* name_array[MAX_ENTRIES];
int count_for_name = 0;
int count_for_addr = 0;
int name_count = 0;

void write_to_json(app_pc start) {
    char current_dir[MAX_PATH_LENGTH];
    size_t dir_length;
    dr_get_current_directory(current_dir, dir_length);
    char output_file[MAX_PATH_LENGTH + sizeof(OUTPUT_FILE)];
    snprintf(output_file, sizeof(output_file), "%s%s", current_dir, OUTPUT_FILE);

    file_t file = dr_open_file(output_file, DR_FILE_WRITE_OVERWRITE);
    if (file == NULL) {
        dr_printf("Failed to open file\n");
        return;
    }

    dr_fprintf(file, "{\n");

    dr_fprintf(file, "  \"start\": \"0x%X\",\n", (DWORD)start);

    dr_fprintf(file, "  \"addr_get_name\": [\n");\

    for (int i = 0; i < count_for_name; i++) {
        dr_fprintf(file, "    \"0x%X\"%s\n", addr_name_array[i], i < count_for_name - 1 ? "," : "");
    }

    dr_fprintf(file, "  ],\n");

    dr_fprintf(file, "  \"addr_get_addr\": [\n");

    for (int i = 0; i < count_for_addr; i++) {
        dr_fprintf(file, "    \"0x%X\"%s\n", addr_address_array[i], i < count_for_addr - 1 ? "," : "");
    }

    dr_fprintf(file, "  ],\n");

    dr_fprintf(file, "  \"resolved_name\": [\n");
    for (int i = 0; i < name_count; i++) {
        dr_fprintf(file, "    \"%s\"%s\n", name_array[i], i < name_count - 1 ? "," : "");
    }

    dr_fprintf(file, "  ]\n");

    dr_fprintf(file, "}\n");
    dr_close_file(file);
}

void free_name_array() {
    for (int i = 0; i < name_count; i++) {
        free(name_array[i]);
    }
}

bool is_pc_exists(DWORD pc, DWORD *array, int count) {
    for (int i = 0; i < count; i++) {
        if (array[i] == pc) {
            return true;
        }
    }
    return false;
}

bool is_name_exists(const char* name) {
    for (int i = 0; i < name_count; i++) {
        if (strcmp(name_array[i], name) == 0) {
            return true;
        }
    }
    return false;
}

void store_pc(DWORD pc, bool is_for_addr) {
    DWORD *array = is_for_addr ? addr_address_array : addr_name_array;
    int *count = is_for_addr ? &count_for_addr : &count_for_name;

    if (!is_pc_exists(pc, array, *count) && *count < MAX_ENTRIES) {
        array[(*count)++] = pc;
    }
}

void store_name(const char* name) {
    if (!is_name_exists(name) && name_count < MAX_ENTRIES) {
        name_array[name_count] = strdup(name);
        name_count++;
    }
}

/*
 * Check in the interval tree if there's the passed value which is the value of the current destination operand (register)
 * for the current instruction instrumented that matches the conditions inside event_bb_analysis()
 */

/*
 * 現在の命令にインストルメントされた現在の宛先オペランド（レジスタ）の値である渡された値が、
 * event_bb_analysis() 内の条件に一致するかどうかをインターバルツリーで確認します。
 */

itreenode_t *is_ExportTableFunctionsReference(PDWORD value)
{
    itreenode_t *tree;
    tree = itree_search_AddressOfFunctions(intervalTree, value); // search for AddressOfFunctions
    // tree = itree_search_ordinals(intervalTree, value);
    // tree = itree_search_NumberOfFunctions(intervalTree, value);
    // tree = itree_search_AddressOfNames(intervalTree, value);
    if (tree) return tree;
    else return NULL;
}

itreenode_t *is_ExportTableNamesReference(PDWORD value)
{
    itreenode_t *tree;
    tree = itree_search_AddressOfNames(intervalTree, value);
    if (tree) return tree;
    else return NULL;
}

int search_for_ordinals_index(itreenode_t *tree, int ordinals)
{
    PWORD ordinals_base = tree->AddressOfNameOrdinals;
    int num = tree->NumberOfFunctions;
    // dr_printf("mod_name: %s, ordinals_base: %x, num: %d\n", tree->mod_name, ordinals_base, num);
    for (int i=0; i<num; i++){
        if (tree->AddressOfNameOrdinals[i] == ordinals)
            return i;   
    }
    return -1;
}


void TestMemoryAccess(app_pc pc, reg_id_t base_id, int disp_id, reg_id_t index_id, int scale_id)
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    dr_get_mcontext(drcontext, &mc);
    reg_t base = dr_read_saved_reg(drcontext, SPILL_SLOT_2);
    int index = reg_get_value(index_id, &mc);
    // dr_printf("addr: %x, base: %x, disp: %x, index: %x, scale: %x\n", pc, base , disp_id, reg_get_value(index_id, &mc), scale_id);
    //         004030a3 8b 34 86        MOV        ESI,dword ptr [ESI + EAX*0x4]
    // ESI (base) is array_of_funcitons, so EAX is array_of_ordinals[j]
    // so, we have to reverse j

    itreenode_t *tree_names = is_ExportTableNamesReference((PDWORD)base);
    if (tree_names != NULL) {
        // dr_printf("[+] AddressOfNames found\n   pc: 0x%X\n", pc);
        store_pc((DWORD)pc, false);
    }

    itreenode_t *tree_functions = is_ExportTableFunctionsReference((PDWORD)base);
    if (tree_functions != NULL) {
        int ordinals = index;
        int api_index = search_for_ordinals_index(tree_functions, ordinals);
        // dr_printf("[+] addr: 0x%x, base: %x, disp: %x, index: %x, scale: %x\n", pc, base , disp_id, reg_get_value(index_id, &mc), scale_id);
        // dr_printf("[*] name: %s, addr: 0x%x\n", (char *)((DWORD_PTR)tree->start_addr + (DWORD) tree->AddressOfNames[index]), pc);
        // dr_printf("    Resolved name: %s\n", (char *)((DWORD_PTR)tree_functions->start_addr + (DWORD) tree_functions->AddressOfNames[api_index]));
        store_pc((DWORD)pc, true);
        store_name((char *)((DWORD_PTR)tree_functions->start_addr + (DWORD) tree_functions->AddressOfNames[api_index]));
    }
}

/*
 * Callback called during the BBs creation event.
 *  drcontext -> pointer to the input program's machine context;
 *  tag -> unique identifier for the basic block fragment;
 *  bb -> a pointer to the list of instructions that comprise the basic block;
 *  for_trace -> indicates whether this callback is for a new basic block (false) or for adding a basic block to a trace being created (true);
 *  translating -> indicates whether this callback is for basic block creation (false) or is for address translation (true).
 *
 * Here we iterate over each instruction of each basic block, checking if the instruction reads from memory (instr_reads_memory() returns true
 * if any of instr's source operands is a memory reference).
 * If yes, we iterate over each destination operand of the current instruction, and if they are registers we save its ID and insert a 
 * clean call (https://dynamorio.org/API_BT.html#sec_clean_call) which inserts into bb priot to next meta-instruction(s) to save state for a call,
 * switch to this thread's DR stack, set up the passed-in params, make a call to RecordMemoryAccess, clean up the parameters and restore the saved state.
 * This clean call is called on the next instruction that matches all the conditions in event_bb_analysis, so after executing it, in this way we 
 * are able to inspect the value of the destination register and check if it's something from the export table.
 */

/*
 * BB生成イベント中に呼ばれるコールバック。
 *  drcontext -> 入力プログラムのマシンコンテキストへのポインター；
 *  tag -> 基本ブロックフラグメントの一意の識別子；
 *  bb -> 基本ブロックを構成する命令のリストへのポインター；
 *  for_trace -> このコールバックが新しい基本ブロック用（false）か、作成中のトレースに基本ブロックを追加する用（true）かを示す；
 *  translating -> このコールバックが基本ブロックの生成用（false）か、アドレス変換用（true）かを示す。
 *
 * ここでは、各基本ブロックの各命令を繰り返し確認し、命令がメモリから読み取るかどうかをチェックします（instr_reads_memory()は、命令のソースオペランドのいずれかがメモリ参照である場合にtrueを返します）。
 * もし読み取る場合、現在の命令の各宛先オペランドに対して繰り返し処理を行い、それらがレジスタの場合はそのIDを保存し、
 * clean call (https://dynamorio.org/API_BT.html#sec_clean_call) を挿入します。これはbbの次のメタ命令の前に状態を保存するために挿入され、
 * このスレッドのDRスタックに切り替え、渡されたパラメータを設定し、RecordMemoryAccessに呼び出しを行い、パラメータをクリーンアップして保存された状態を復元します。
 * このclean callは、event_bb_analysisのすべての条件に一致する次の命令で呼び出されるため、これを実行した後、
 * 出力テーブルからの何かであるかどうかを目的のレジスタの値を検査できます。
 */

static dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating, OUT void **user_data)
{
    instr_t *instr, *next;
    instr = instrlist_first(bb);
    app_pc pc = instr_get_app_pc(instr);
    if (!dr_module_contains_addr(main_mod, (BYTE *)pc)) return DR_EMIT_DEFAULT; // Skip if current bb is not in program code (but library code)

    for (instr; instr != NULL; instr = next) {
        if (instr_reads_memory(instr)) {
            app_pc address = instr_get_app_pc(instr);
            // dr_printf("pc: %x\n", address);
            uint opcode = instr_get_opcode(instr);
            next = instr_get_next(instr);
            opnd_t opnd_src;
            for (int i=0; i < instr_num_srcs(instr); i++) {
                opnd_src = instr_get_src(instr, i);
                if (opnd_is_memory_reference(opnd_src) && opnd_is_base_disp(opnd_src)) {
                    reg_id_t reg_base = opnd_get_base(opnd_src); // Assumes opnd is a (near or far) base+disp memory reference. Returns the base register (a DR_REG_ constant).
                    if (reg_base == DR_REG_NULL) {
                        continue;
                    }

                    reg_id_t index = opnd_get_index(opnd_src); // Assumes opnd is a (near or far) base+disp memory reference. Returns the index register (a DR_REG_ constant).
                    int reg_disp = opnd_get_disp(opnd_src);
                    int scale = opnd_get_scale(opnd_src);
                    // if (int(address) == 0x4d129e) {
                    //     dr_printf("reg_base: %x\n", reg_base);
                    //     dr_printf("index: %x\n", index);
                    //     dr_printf("disp: %x\n", reg_disp);
                    //     dr_printf("scale: %x\n", scale);
                    // }

                    dr_save_reg(drcontext, bb, instr, reg_base, SPILL_SLOT_2); // Save the value of EAX prior to instr(CPUID)
                    // Get the saved value for EAX
                    dr_insert_clean_call(drcontext, bb, next, (void *)TestMemoryAccess, false, 5, OPND_CREATE_INTPTR(address), OPND_CREATE_INT32(reg_base), OPND_CREATE_INT32(reg_disp), OPND_CREATE_INT32(index), OPND_CREATE_INT32(scale)); 
                }
            }
        }
        else next = instr_get_next(instr);
    }

    return DR_EMIT_DEFAULT;
}

/*
 * Callback called during the module load event.
 * For each DLL loaded, we calculate the values for the export table's interesting fields and insert them in the interval tree
 * so we can lookup for the values later on.
 */

/*
 * モジュールロードイベント時に呼び出されるコールバック。
 * 各DLLがロードされるたびに、エクスポートテーブルの興味深いフィールドの値を計算し、それらをインターバルツリーに挿入して、
 * 後で値を検索できるようにします。
 */

void event_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    // TODO: refine with all uppercase module names
    // Skip current process and dynamorio's DLLs
    if ((mod->start == main_mod->start && mod->end == main_mod->end) || \
        strstr(mod->full_path, "dr_client.dll") != NULL || \
        strstr(mod->full_path, "dynamorio.dll") != NULL || \
        strstr(mod->full_path, "drmgr.dll") != NULL || \
        strstr(mod->full_path, "drwrap.dll") != NULL
        )
        return;

    // Get name for the current module
    char *mod_name = (char *)dr_module_preferred_name(mod);
    // Get Export Table VA
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)mod->preferred_base;
    PIMAGE_NT_HEADERS32 nt_header = (PIMAGE_NT_HEADERS32)((DWORD_PTR)mod->preferred_base + dos_header->e_lfanew);
	DWORD_PTR exportDir_RVA = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)mod->preferred_base + exportDir_RVA);
	// Get addresses to interesting fields of export table
    DWORD NumberOfFunctions = exportDir->NumberOfFunctions;
     // AddressOfNames is an array of RVAs to function names
	PDWORD AddressOfNames_RVA = (PDWORD)((DWORD_PTR)mod->preferred_base + exportDir->AddressOfNames);
	PDWORD AddressOfFunctions_RVA = (PDWORD)((DWORD_PTR)mod->preferred_base + exportDir->AddressOfFunctions);
	PWORD AddressOfNameOrdinals_RVA = (PWORD)((DWORD_PTR)mod->preferred_base + exportDir->AddressOfNameOrdinals);
    // dr_printf("[+] Loading module %s\n    Range: [0x%X, 0x%X]\n    NumberOfFunctions: %d\t\tAddressOfNames: 0x%X\n    AddressOfFunctions: 0x%X\tAddressOfNameOrdinals: 0x%X\n", mod_name, mod->start, mod->end - 1, NumberOfFunctions, AddressOfNames_RVA, AddressOfFunctions_RVA, AddressOfNameOrdinals_RVA);
    
    // Add module in the interval tree
    if (intervalTree == NULL) { // First time, init
        intervalTree = itree_init(mod->preferred_base, mod->end - 1, mod_name, NumberOfFunctions, AddressOfFunctions_RVA, AddressOfNames_RVA, AddressOfNameOrdinals_RVA);
    } else {
        itree_insert(intervalTree, mod->preferred_base, mod->end - 1, mod_name, NumberOfFunctions, AddressOfFunctions_RVA, AddressOfNames_RVA, AddressOfNameOrdinals_RVA);
    }   
}

static void exit_event(void)
{
#ifdef _DEBUG_TREE
    itree_print(intervalTree);
    if (itree_verify(intervalTree)) dr_printf("<DBG> : all good in the itree!\n");
#endif
    dr_printf("Done! Hope you got nice results, bye!\nNext, Ghidra Headless Analyzer is launching!\n");
    // for (int i=0; i<pc_count; i++) dr_printf("pc: 0x%x\n", pc_array[i]);
    // for (int i=0; i<name_count; i++) dr_printf("resolved name: %s\n", name_array[i]);
    write_to_json(main_mod->start);

    // Cleanup data structures
    dr_free_module_data(main_mod);
    itree_dealloc(intervalTree);
    // Cleanup extensions
    drmgr_exit();
    drwrap_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("Export Table Memory Accesses Logger", "");
    if (!drmgr_init() || !drwrap_init()) DR_ASSERT_MSG(false, "Error initializing extensions");

    dr_enable_console_printing();
    dr_printf("Starting analysis..\n");
    // Looks up module data for the main executable
    main_mod = dr_get_main_module();
    // app_pc entry = main_mod->entry_point;
    // dr_printf("entry: 0x%x\n", int(entry));
    app_pc start = main_mod->start;
    dr_printf("start: 0x%x\n", int(start));

    // Last event called before exiting, used for cleanup of data structures and extensions
    dr_register_exit_event(exit_event);
    // Callback called everytime a module is loaded
    drmgr_register_module_load_event(event_module_load);
    // Callback function called before execution of every piece of code (through this hook you can see all application's code) 
    drmgr_register_bb_instrumentation_event(event_bb_analysis, NULL, NULL);
}
