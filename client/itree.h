#pragma once

#include "dr_api.h"
#include <stdlib.h> // For malloc

#undef _DEBUG_TREE

typedef struct _itreenode_t {
    app_pc start_addr, end_addr;
    struct _itreenode_t *left, *right;
    char *mod_name;
    DWORD NumberOfFunctions; // Total number of exported functions, either by name or ordinal
    PDWORD AddressOfFunctions; // A RVA to the list of exported functions - it points to an array of NumberOfFunctions 32-bit values, each being a RVA to the exported function or variable
    PDWORD AddressOfNames; // A RVA to the list of exported names - it points to an array of NumberOfNames 32-bit values, each being a RVA to the exported symbol name
    PWORD AddressOfNameOrdinals; // A RVA to the list of ordinals - it points to an array of NumberOfNames 16-bit values, each being an ordina
} itreenode_t;

itreenode_t *itree_init(app_pc start, app_pc end, char *name, DWORD n_func, PDWORD addr_func, PDWORD addr_names, PWORD addr_namesOrd);
bool itree_insert(itreenode_t *tree, app_pc start, app_pc end, char *name, DWORD n_func, PDWORD addr_func, PDWORD addr_names, PWORD addr_namesOrd);
itreenode_t *itree_search_AddressOfFunctions(itreenode_t *tree, PDWORD value);
// itreenode_t *itree_search_ordinals(itreenode_t *tree, PWORD value);
// itreenode_t *itree_search_NumberOfFunctions(itreenode_t *tree, PDWORD value);
itreenode_t *itree_search_AddressOfNames(itreenode_t *tree, PDWORD value);
bool itree_dealloc(itreenode_t *tree);
void itree_print(itreenode_t *node);
bool itree_verify(itreenode_t *tree);