#define _CRT_SECURE_NO_WARNINGS
#define MAX_ENTRIES 1000
#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"

#include "itree.h"
#include "searching.h"

#include <stdlib.h>
#include <malloc.h>

static void exit_event_callback(void);
static void module_load_event_callback(void *drcontext, const module_data_t *mod, bool loaded);
static dr_emit_flags_t bb_event(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, bool for_trace, bool translating, void *user_data);
static dr_emit_flags_t  bb_instrumentation_event_callback(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, bool for_trace, bool translating, void *user_data);

module_data_t *main_mod;
DWORD addr_name_array[MAX_ENTRIES];
DWORD addr_address_array[MAX_ENTRIES];
char* name_array[MAX_ENTRIES];
int count_for_name;
int count_for_addr;
int name_count;
char current_dir[MAX_PATH];
size_t dir_length;


extern itreenode_t *itree;

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if (!drmgr_init() || !drwrap_init()) DR_ASSERT_MSG(false, "Error initializing extensions");

    dr_enable_console_printing();
    dr_printf("[*] Analysis starting..\n");
    name_count = 0;
    count_for_addr = 0;
    count_for_name = 0;

    // Get main module information
    main_mod = dr_get_main_module();

    write_file_init();

    // Register event's callbacks
    dr_register_exit_event(exit_event_callback);
    drmgr_register_module_load_event(module_load_event_callback);
    drmgr_register_bb_instrumentation_event(NULL, bb_instrumentation_event_callback, NULL);
}

static void exit_event_callback(void)
{
    dr_printf("[*] Analysis terminated.\n");
    free_name_array();

    dr_free_module_data(main_mod);
    itree_dealloc(itree);

    drmgr_unregister_module_load_event(module_load_event_callback);
    drmgr_unregister_bb_insertion_event(bb_instrumentation_event_callback);
    
    drwrap_exit();
    drmgr_exit();
}

static void module_load_event_callback(void *drcontext, const module_data_t *mod, bool loaded)
{
    char *img_name_lwr = _strlwr(_strdup(dr_module_preferred_name(mod)));

    /* Ignore the current sample and DynamoRIO's libraries */
    if ((mod->start == main_mod->start && mod->end == main_mod->end) ||
        strstr(img_name_lwr, "api_deob.dll") != NULL ||
        strstr(img_name_lwr, "dynamorio.dll") != NULL ||
        strstr(img_name_lwr, "drmgr.dll") != NULL ||
        strstr(img_name_lwr, "drwrap.dll") != NULL)
        return;

    /* Traverse the PE header of the current module */
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)mod->preferred_base;
    PIMAGE_NT_HEADERS32 nt_header = (PIMAGE_NT_HEADERS32)((DWORD_PTR)mod->preferred_base + dos_header->e_lfanew);
    DWORD_PTR exportDir_RVA = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir_VA = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)mod->preferred_base + exportDir_RVA);
    /* Traverse the export table */
    DWORD numberOfFunctions = exportDir_VA->NumberOfFunctions;
    DWORD numberOfNames = exportDir_VA->NumberOfNames;
    PDWORD addressOfFunctions_RVA = (PDWORD)((DWORD_PTR)mod->preferred_base + exportDir_VA->AddressOfFunctions);
    PDWORD addressOfNames_RVA = (PDWORD)((DWORD_PTR)mod->preferred_base + exportDir_VA->AddressOfNames);
    PWORD addressOfNameOrdinals_RVA = (PWORD)((DWORD_PTR)mod->preferred_base + exportDir_VA->AddressOfNameOrdinals);

    // DWORD minValue = addressOfNames_RVA[0];
    // DWORD maxValue = addressOfNames_RVA[0];
    // for (DWORD i = 1; i < numberOfFunctions; i++) {
    //     DWORD value = addressOfNames_RVA[i];
    //     if (value < minValue) {
    //         minValue = value;
    //     }
    //     if (value > maxValue) {
    //         maxValue = value;
    //     }
    // }
    // dr_printf("[%s]\n", img_name_lwr);
    // dr_printf("addr 0x%X to 0x%X\n\n", minValue, maxValue);
    

    /* Update/init the interval tree */
    if (itree == NULL)
        itree = itree_init(mod->start, mod->end - 1, img_name_lwr, numberOfFunctions, numberOfNames, addressOfFunctions_RVA, addressOfNames_RVA, addressOfNameOrdinals_RVA);
    else
        itree_insert(itree, mod->start, mod->end - 1, img_name_lwr, numberOfFunctions, numberOfNames, addressOfFunctions_RVA, addressOfNames_RVA, addressOfNameOrdinals_RVA);

    free((void *)img_name_lwr);
}

static dr_emit_flags_t bb_instrumentation_event_callback(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, bool for_trace, bool translating, void *user_data)
{
    app_pc pc = instr_get_app_pc(instr);
    if (!dr_module_contains_addr(main_mod, (BYTE *)pc)) {
        /* Skip if it is not program code */
        return DR_EMIT_DEFAULT;
    }

    if (instr_get_opcode(instr) != OP_lea) {
        dr_insert_clean_call(drcontext, bb, instr, (void *)search_export_table_reference, false, 1, OPND_CREATE_INTPTR(pc));
    }
    // TODO: manage lea case as it may be used for sum operations
    
    //if ((pc == main_mod->start + 0x1206) && instr_is_call(instr))
        //dr_insert_clean_call(drcontext, bb, instr, (void *)instrument_calls, false, 1, OPND_CREATE_INTPTR(pc));

    return DR_EMIT_DEFAULT;
}