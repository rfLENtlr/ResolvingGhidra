#include "dr_api.h"

#include "itree.h"

// For malloc() and free()
#include <stdlib.h>

/* Global reference to the interval tree */
itreenode_t *itree;

itreenode_t *itree_init(app_pc start_addr, app_pc end_addr, char *img_name, DWORD NumberOfFunctions, PDWORD AddressOfFunctions, PDWORD AddressOfNames, PWORD AddressOfNameOrdinals, DWORD name_RVA_first, DWORD name_RVA_last)
{
    itreenode_t *tree = (itreenode_t *)malloc(sizeof(itreenode_t));
    if (tree == NULL) DR_ASSERT_MSG(false, "Failed to initialize intervcal tree");

    /* Initialize values */
    tree->start_addr = start_addr;
    tree->end_addr = end_addr;
    tree->left = NULL;
    tree->right = NULL;
    tree->img_name = _strdup(img_name);
    tree->NumberOfFunctions = NumberOfFunctions;
    tree->AddressOfFunctions = AddressOfFunctions;
    tree->AddressOfNames = AddressOfNames;
    tree->AddressOfNameOrdinals = AddressOfNameOrdinals;
    tree->name_RVA_first = name_RVA_first;
    tree->name_RVA_last = name_RVA_last;
    
    return tree;
}

bool itree_insert(itreenode_t *tree, app_pc start_addr, app_pc end_addr, char *img_name, DWORD NumberOfFunctions, PDWORD AddressOfFunctions, PDWORD AddressOfNames, PWORD AddressOfNameOrdinals, DWORD name_RVA_first, DWORD name_RVA_last)
{
    itreenode_t *temp = tree;

    if (temp->start_addr == start_addr && temp->end_addr == end_addr)
        return false;
    else if (temp->end_addr < start_addr) /* Insert in right subtree */
    {
        if (temp->right) /* Right subtree persent */
            return itree_insert(temp->right, start_addr, end_addr, img_name, NumberOfFunctions, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals, name_RVA_first, name_RVA_last);
        else /* Right subtree NOT present */
        {
            temp->right = itree_init(start_addr, end_addr, img_name, NumberOfFunctions, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals, name_RVA_first, name_RVA_last);
            return true;
        }
    }
    else /* Insert in left subtree */
    {
        if (temp->left) /* Left subtree persent */
            return itree_insert(temp->left, start_addr, end_addr, img_name, NumberOfFunctions, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals, name_RVA_first, name_RVA_last);
        else /* Left subtree NOT present */
        {
            temp->left = itree_init(start_addr, end_addr, img_name, NumberOfFunctions, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals, name_RVA_first, name_RVA_last);
            return true;
        }
    }

    return false;
}

itreenode_t *check_DllBaseAddress(itreenode_t *tree, app_pc address)
{
    if (!tree) return NULL;
    itreenode_t *temp = tree;
    
    if (address == temp->start_addr)
        return temp;
    else if (temp->end_addr < address)
        if (temp->right)
            return check_DllBaseAddress(temp->right, address);
        else
            return NULL;
    else 
        if (temp->left)
            return check_DllBaseAddress(temp->left, address);
        else
            return NULL;
    
    return NULL;
}

itreenode_t *check_AddressOfNames(itreenode_t *tree, DWORD offset)
{
    if (!tree) return NULL;
    itreenode_t *temp = tree;
    
    if (offset >= temp->name_RVA_first && offset <= temp->name_RVA_last)
        return temp;
    else if (temp->name_RVA_first < offset)
        if (temp->right)
            return check_AddressOfNames(temp->right, offset);
        else
            return NULL;
    else 
        if (temp->left)
            return check_AddressOfNames(temp->left, offset);
        else
            return NULL;
    
    return NULL;
}

itreenode_t *itree_search(itreenode_t *tree, PDWORD value, SearchAddress field)
{
    if (!tree) return NULL;

    itreenode_t *temp = tree;
    PDWORD cmp_val = (field == SEARCH_ADDR_NAMES) ? temp->AddressOfNames : temp->AddressOfFunctions;

    if (value == cmp_val) {
        /* Value found */
        return temp;
    }
    else if (cmp_val < value) {
        if (temp->right) {
            /* Search in the right portion */
            return itree_search(temp->right, value, field);
        }
        else return NULL;
    } else {
        if (temp->left) {
            /* Search in the left portion */
            return itree_search(temp->left, value, field);
        }
        else return NULL;
    }

    return NULL;
}

bool itree_dealloc(itreenode_t *tree)
{
    if (!tree) return true;

	itreenode_t *temp = tree;
	itreenode_t *right = tree->right;
	itreenode_t *left = tree->left;
	free(tree->img_name);
    free(tree);

	if (right) {
		itree_dealloc(right);
    }

    if (left) {
		itree_dealloc(left);
    }

	return true;
}

void itree_print(itreenode_t *node)
{
	if (!node)
		return;

    static int lvl = 1;
    dr_printf("Level: %u, Range: [0x%x, 0x%x], Module name: %s, AddressOfFunctions: 0x%x\n", lvl, node->start_addr, node->end_addr, node->img_name, node->AddressOfFunctions);
    lvl += 1;

	itree_print(node->left);
	itree_print(node->right);

	return;
}

bool itree_verify(itreenode_t *tree)
{
	if (!tree) return true;

	/* Well-formed interval: redundant */
	if (tree->end_addr <= tree->start_addr) 
    {
        dr_printf("End address less than start address, module=%s\n", tree->img_name);
        return false;
    }

	/* Left child contains interval ending beyond the parent interval's start */
	if (tree->left && tree->left->AddressOfFunctions >= tree->AddressOfFunctions)
    {
        dr_printf("Second check failed for %s\n\t[%d]\t[%d]\n", tree->img_name, tree->AddressOfFunctions, tree->left->AddressOfFunctions);
        return false;
    }
	/* Right child contains interval starting before the parent interval's end */
	if (tree->right && tree->right->AddressOfFunctions <= tree->AddressOfFunctions)
    {
        dr_printf("Third check failed for %s\n", tree->img_name);
        return false;
    }

	return (itree_verify(tree->left) && itree_verify(tree->right));
}