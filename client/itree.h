#pragma once

typedef struct _itreenode_t {
    app_pc start_addr, end_addr;
    struct _itreenode_t *left, *right;
    char *img_name;
    DWORD NumberOfFunctions, NumberOfNames;
    PDWORD AddressOfFunctions;
    PDWORD AddressOfNames;
    PWORD AddressOfNameOrdinals;
} itreenode_t;

typedef enum {
    SEARCH_ADDR_NAMES,
    SEARCH_ADDR_FUNCS
} SearchAddress;

itreenode_t *itree_init(app_pc start_addr, app_pc end_addr, char *img_name, DWORD NumberOfFunctions, DWORD NumberOfNames, PDWORD AddressOfFunctions, PDWORD AddressOfNames, PWORD AddressOfNameOrdinals);
bool itree_insert(itreenode_t *tree, app_pc start_addr, app_pc end_addr, char *img_name, DWORD NumberOfFunctions, DWORD NumberOfNames, PDWORD AddressOfFunctions, PDWORD AddressOfNames, PWORD AddressOfNameOrdinals);
itreenode_t *check_DllBaseAddress(itreenode_t *tree, app_pc address);
// itreenode_t *check_AddressOfNames(itreenode_t *tree, DWORD offset);
itreenode_t *itree_search(itreenode_t *tree, PDWORD value, SearchAddress field);
bool itree_dealloc(itreenode_t *tree);
void itree_print(itreenode_t *node);
bool itree_verify(itreenode_t *tree);