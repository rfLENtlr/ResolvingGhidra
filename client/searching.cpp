#define MAX_ENTRIES 1000
#define OUTPATH "..\\out\\dbi\\"

#include "dr_api.h"

#include <math.h>

#include "searching.h"
#include "itree.h"

#include <stdio.h>
#include <stdlib.h>

/* Extern variables */
extern itreenode_t *itree;
extern module_data_t *main_mod;
extern DWORD addr_name_array[MAX_ENTRIES];
extern DWORD addr_address_array[MAX_ENTRIES];
extern char* name_array[MAX_ENTRIES];
extern int count_for_name;
extern int count_for_addr;
extern int name_count;

char logname[MAX_PATH];

/* Functions declaration */
static bool search_in_lea(void *drcontext, instr_t *instr, dr_mcontext_t *mc, app_pc pc);
static bool search_in_others(void *drcontext, instr_t *instr, dr_mcontext_t *mc, app_pc pc);
instr_t *decode_instruction(void *drcontext, app_pc pc); // May be moved to an utils file instead
bool search_address_of_names(void *drcontext, instr_t *instr, dr_mcontext_t *mc, app_pc pc);
itreenode_t *search_img_base(void *drcontext, app_pc pc, opnd_t opnd, dr_mcontext_t *mc);
bool search_name_offset(void *drcontext, app_pc pc, opnd_t opnd, itreenode_t *tree, dr_mcontext_t *mc);
bool search_address_of_functions(void *drcontext, instr_t *instr, dr_mcontext_t *mc, app_pc pc);
static bool search_function_address(void *drcontext, app_pc pc, opnd_t opnd, itreenode_t *tree, dr_mcontext_t *mc);
static void log_func_address(void *drcontext, itreenode_t *tree, DWORD index, app_pc pc);

void write_file_init();
void write_to_json();
void free_name_array();
bool is_pc_exists(DWORD pc, DWORD *array, int count);
bool is_name_exists(const char *name);
void store_pc(DWORD pc, bool is_for_addr);
void store_name(const char *name);

void search_export_table_reference(app_pc pc)
{
    void *drcontext = dr_get_current_drcontext();
    instr_t *instr = decode_instruction(drcontext, pc);
    if (instr == NULL) {
        return;
    }

    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    dr_get_mcontext(drcontext, &mc);

    if (instr_get_opcode(instr) == OP_lea) {
        search_in_lea(drcontext, instr, &mc, pc);
    }
    else {
        search_in_others(drcontext, instr, &mc, pc);
    }

    instr_destroy(drcontext, instr);
}

instr_t *decode_instruction(void *drcontext, app_pc pc)
{
    instr_t *instr = instr_create(drcontext);
    if (!decode(drcontext, pc, instr)) {
        instr_destroy(drcontext, instr);
        return NULL;
    }

    return instr;
}

static bool search_in_lea(void *drcontext, instr_t *instr, dr_mcontext_t *mc, app_pc pc)
{
    //TODO: manage the case for AddressOfFunctions
    if (instr_num_srcs(instr) <= 0) {
        return false;
    }

    itreenode_t *tree = NULL;
    opnd_t opnd = instr_get_src(instr, 0); // Do I need to check other dst operands with a for loop?

    reg_t base_val = reg_get_value(opnd_get_base(opnd), mc);
    reg_t index_val = reg_get_value(opnd_get_index(opnd), mc);
    int scale = opnd_get_scale(opnd);
    int disp = opnd_get_disp(opnd);

    tree = check_DllBaseAddress(itree, (app_pc)base_val);
    if (tree) {
        if ((DWORD)index_val >= tree->AddressOfNames[0] && (DWORD)index_val <= tree->AddressOfNames[tree->NumberOfFunctions - 1]) {
        // if ((DWORD)index_val >= tree->name_RVA_first && (DWORD)index_val <= tree->name_RVA_last) {
            // log_api_name(drcontext, tree, (DWORD)index_val, pc);
            store_pc((DWORD)pc, false);
            write_to_json();
            return true;
        }
    }
    else {
        tree = check_DllBaseAddress(itree, (app_pc)index_val);
        if (tree) {
        if ((DWORD)index_val >= tree->AddressOfNames[0] && (DWORD)index_val <= tree->AddressOfNames[tree->NumberOfFunctions - 1]) {
            // if ((DWORD)base_val >= tree->name_RVA_first && (DWORD)base_val <= tree->name_RVA_last) {
                // log_api_name(drcontext, tree, (DWORD)base_val, pc);
                store_pc((DWORD)pc, false);
                write_to_json();
                return true;
            }
        }
    }
    return false;
}

static bool search_in_others(void *drcontext, instr_t *instr, dr_mcontext_t *mc, app_pc pc)
{
    if (instr_num_dsts(instr) <= 0 || instr_num_srcs(instr) <= 0) {
        return false;
    }

    itreenode_t *tree = NULL;
    opnd_t opnd_dst = instr_get_dst(instr, 0); // Do I need to check other dst operands with a for loop?
    opnd_t opnd_src = instr_get_src(instr, 0);

    tree = search_img_base(drcontext, pc, opnd_dst, mc);
    if (tree) {
        if (!search_name_offset(drcontext, pc, opnd_src, tree, mc))
            search_function_address(drcontext, pc, opnd_src, tree, mc);
    }
    else {
        tree = search_img_base(drcontext, pc, opnd_src, mc);
        if (tree) {
            if (!search_name_offset(drcontext, pc, opnd_dst, tree, mc))
                search_function_address(drcontext, pc, opnd_dst, tree, mc);
        }
    }
    return false;
}

itreenode_t *search_img_base(void *drcontext, app_pc pc, opnd_t opnd, dr_mcontext_t *mc)
{
    reg_t base_val = 0, index_val = 0;
    int scale = 0, disp = 0;
    DWORD value = 0;
    itreenode_t *tree = NULL;

    if (opnd_is_reg(opnd) && reg_is_gpr(opnd_get_reg(opnd))) {
        /* OPND is register, check if it contains DLL base address */
        reg_t val = reg_get_value(opnd_get_reg(opnd), mc);
        tree = check_DllBaseAddress(itree, (app_pc)val);
    }
    else if (opnd_is_base_disp(opnd)) {
        /* OPND is base+disp, check if references DLL base address */
        reg_t base_val = reg_get_value(opnd_get_base(opnd), mc);
        reg_t index_val = reg_get_value(opnd_get_index(opnd), mc);
        int scale = opnd_get_scale(opnd);
        int disp = opnd_get_disp(opnd);
        if (!base_val && !index_val) return tree;
        
        DWORD val = *(PDWORD)(base_val + index_val * scale + disp);
        tree = check_DllBaseAddress(itree, (app_pc)val);
    }

    return tree;
}

bool search_name_offset(void *drcontext, app_pc pc, opnd_t opnd, itreenode_t *tree, dr_mcontext_t *mc)
{
    // TODO: manage case opnd_is_abs_addr() ?
    if (opnd_is_reg(opnd) && reg_is_gpr(opnd_get_reg(opnd))) {
        /* OPND is register, check if it contains name offset for found DLL */
        reg_t val = reg_get_value(opnd_get_reg(opnd), mc);
        if ((DWORD)val >= tree->AddressOfNames[0] && (DWORD)val <= tree->AddressOfNames[tree->NumberOfFunctions - 1]) {
        // if ((DWORD)val >= *(tree->AddressOfNames) && (DWORD)val <= *(tree->AddressOfNames) + tree->NumberOfFunctions) {
            /* Confirm if the value in range is a valid offset */
            for (DWORD j = 0; j < tree->NumberOfNames; j++) {
                if (val == tree->AddressOfNames[j]) {
                    store_pc((DWORD)pc, false);
                    write_to_json();
                    // dr_printf("API: %s\n", (char*)(tree->start_addr + val));
                    return true;
                }
            }
        }
    }
    if (opnd_is_base_disp(opnd)) {
        /* OPND is base+disp, check if references name offset for found DLL */
        reg_t base_val = reg_get_value(opnd_get_base(opnd), mc);
        reg_t index_val = reg_get_value(opnd_get_index(opnd), mc);
        int scale = opnd_get_scale(opnd);
        int disp = opnd_get_disp(opnd);
        if (!base_val && !index_val) return false;

        DWORD val = base_val + index_val * scale + disp;
        if (val >= *(tree->AddressOfNames) && val <= *(tree->AddressOfNames) + tree->NumberOfFunctions) {
            store_pc((DWORD)pc, false);
            write_to_json();
            return true;
        }
    }

    return false;
}

// bool search_address_of_functions(void *drcontext, instr_t *instr, dr_mcontext_t *mc, app_pc pc)
// {
    
//     if (instr_num_srcs(instr) <= 0) {
//         return false;
//     }

//     opnd_t opnd_src = instr_get_src(instr, 0);
//     if (!opnd_is_base_disp(opnd_src)) { // opnd_is_memory_reference?
//         return false;
//     }

//     reg_t base_val = reg_get_value(opnd_get_base(opnd_src), mc);
//     reg_t index_val = reg_get_value(opnd_get_index(opnd_src), mc);
//     int scale = opnd_get_scale(opnd_src);
//     int disp = opnd_get_disp(opnd_src);
//     if (!base_val && !index_val) return false;

//     itreenode_t *tree = itree_search(itree, (PDWORD)base_val, SEARCH_ADDR_FUNCS);
//     if (tree) {
//         store_pc((DWORD)pc, true);
//         int index = 0;
//         for (DWORD i = 0; i < tree->NumberOfFunctions; i++) {
//             /* Reverse the index */
//             if (tree->AddressOfNameOrdinals[i] == index_val)
//                 index = i;
//         }
        
//         /* Compute the API name */
//         char *api_name = (char *)((DWORD_PTR)tree->start_addr + (DWORD)tree->AddressOfNames[index]);
//         // dr_printf(">> API-name: %s\n", api_name);
//         store_name(api_name);
//         write_to_json();
//     }

//     return true;
// }

static bool search_function_address(void *drcontext, app_pc pc, opnd_t opnd, itreenode_t *tree, dr_mcontext_t *mc)
{
    if (opnd_is_reg(opnd) && reg_is_gpr(opnd_get_reg(opnd))) {
        reg_t val = reg_get_value(opnd_get_reg(opnd), mc);
        if (!val) return false;
        for (DWORD j = 0; j < tree->NumberOfNames; j++) {
            if (tree->AddressOfFunctions[tree->AddressOfNameOrdinals[j]] == val) {
                log_func_address(drcontext, tree, j, pc);
                return true;
            }
        }
    }
    if (opnd_is_base_disp(opnd)) {
        reg_t base_val = reg_get_value(opnd_get_base(opnd), mc);
        reg_t index_val = reg_get_value(opnd_get_index(opnd), mc);
        int scale = opnd_get_scale(opnd);
        int disp = opnd_get_disp(opnd);
        if (!base_val && !index_val) return false;
        DWORD val = *(PDWORD)(base_val + index_val * scale + disp);
        if (!val) return false;        
        for (DWORD j = 0; j < tree->NumberOfNames; j++) {
            if (tree->AddressOfFunctions[tree->AddressOfNameOrdinals[j]] == val) {
                log_func_address(drcontext, tree, j, pc);
                // store_pc(pc);
                return true;
            }
        }
    }

    return false;
}

void write_file_init() {
    char *sample_name = _strdup(main_mod->names.exe_name);
    _splitpath(sample_name, NULL, NULL, sample_name, NULL);
    strcpy_s(logname, OUTPATH);
    strcat_s(logname, sample_name);
    strcat_s(logname, ".json");
}


void write_to_json() {
    // char logname[MAX_PATH];
    // char *sample_name = _strdup(main_mod->names.exe_name);
    // _splitpath(sample_name, NULL, NULL, sample_name, NULL);
    // strcpy_s(logname, OUTPATH);
    // strcat_s(logname, sample_name);
    // strcat_s(logname, ".json");

    file_t file = dr_open_file(logname, DR_FILE_WRITE_OVERWRITE);
    if (file == NULL) {
        dr_printf("Failed to open file\n");
        return;
    }

    dr_fprintf(file, "{\n");

    dr_fprintf(file, "  \"start\": \"0x%X\",\n", (DWORD)main_mod->start);

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
    // dr_printf("name count: %d\n", count_for_name);
    // dr_printf("addr count: %d\n", count_for_addr);
    DWORD *array = is_for_addr ? addr_address_array : addr_name_array;
    int *count = is_for_addr ? &count_for_addr : &count_for_name;

    if (!is_pc_exists(pc, array, *count) && *count < MAX_ENTRIES) {
        array[(*count)++] = pc;
    }
    // dr_printf("updated name count: %d\n", count_for_name);
    // dr_printf("updated addr count: %d\n", count_for_addr);
}

void store_name(const char* name) {
    if (!is_name_exists(name) && name_count < MAX_ENTRIES) {
        name_array[name_count] = _strdup(name);
        name_count++;
    }
}

static void log_func_address(void *drcontext, itreenode_t *tree, DWORD index, app_pc pc)
{
    /* Compute the API name */
    char *api_name = (char *)((DWORD_PTR)tree->start_addr + (DWORD)tree->AddressOfNames[index]);
    // LOG_PRINT("AddressOfFunctions @ %x - Name: %s, from: %s", pc, api_name, tree->img_name);
    // DBG_PRINT(
    //     ">> Found AddressOfFunctions (0x%x) in module %s. The instruction is at address "
    //     "[0x%x]\n   AddressOfNameOrdinals[i]=0x%x (AddressOfNameOrdinals=0x%x), API-name: %s",
    //     tree->AddressOfFunctions, tree->img_name, pc, tree->AddressOfNameOrdinals[index], tree->AddressOfNameOrdinals, api_name);
    // DEBUG_INSTRUCTION(drcontext, pc);
    store_pc((DWORD)pc, true);
    store_name(api_name);
    write_to_json();
}