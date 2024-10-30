#include "itree.h"


itreenode_t *itree_init(app_pc start, app_pc end, char *name, DWORD n_func, PDWORD addr_func, PDWORD addr_names, PWORD addr_namesOrd)
{
    itreenode_t *tree = (itreenode_t *)malloc(sizeof(itreenode_t));
    if (tree == NULL) {
        DR_ASSERT_MSG(false, "Failed to initiliaze interval tree");
    }

    tree->start_addr = start;
    tree->end_addr = end;
    tree->left = NULL;
    tree->right = NULL;
    tree->mod_name = _strdup(name);
    tree->NumberOfFunctions = n_func;
    tree->AddressOfFunctions = addr_func;
    tree->AddressOfNames = addr_names;
    tree->AddressOfNameOrdinals = addr_namesOrd;
    
    return tree;
}

bool itree_insert(itreenode_t *tree, app_pc start, app_pc end, char *name, DWORD n_func, PDWORD addr_func, PDWORD addr_names, PWORD addr_namesOrd)
{
    itreenode_t *temp = tree;

    // Skip if current module is already present
    if (temp->start_addr == start && temp->end_addr == end)
        return false;
    else if (temp->AddressOfFunctions < addr_func) // Insert in right subtree
    {
        if (temp->right)
            return itree_insert(temp->right, start, end, name, n_func, addr_func, addr_names, addr_namesOrd);
        else
        {
            // Right subtree not present -> init new node
            temp->right = itree_init(start, end, name, n_func, addr_func, addr_names, addr_namesOrd);
            return true;
        }
    }
    else // Insert in left subtree
    {
        if (temp->left)
            return itree_insert(temp->left, start, end, name, n_func, addr_func, addr_names, addr_namesOrd);
        else
        {
            // Left subtree not present -> init new node
            temp->left = itree_init(start, end, name, n_func, addr_func, addr_names, addr_namesOrd);
            return true;
        }
    }

    return false;
}

itreenode_t *itree_search_AddressOfFunctions(itreenode_t *tree, PDWORD value)
{
    if (!tree) return NULL;

    itreenode_t *temp = tree;

    // value >= temp->AddressOfFunctions && value < temp->AddressOfFunctions + temp->NumberOfFunctions * sizeof(DWORD)
    // if (value == /*(uint32_t)*/temp->AddressOfFunctions) {

    // with this we can find all the accesses made within the AddressOfFunctions array
    // so that we can compute the offset from the base of the array and reverse the computation
    // to be able to compute the `j`
    // if (value >= temp->AddressOfFunctions && value < temp->AddressOfFunctions + temp->NumberOfFunctions * sizeof(DWORD)) {
    if (value == temp->AddressOfFunctions) {
        // Value found
        return temp;
    }
    else if (/*(uint32_t)*/temp->AddressOfFunctions < value) {
        if (temp->right) {
            // Search in the right part
            return itree_search_AddressOfFunctions(temp->right, value);
        }
        else return NULL;
    } else {
        if (temp->left) {
            // Search in the left part
            return itree_search_AddressOfFunctions(temp->left, value);
        }
        else return NULL;
    }

    return NULL;
}

itreenode_t *itree_search_AddressOfNames(itreenode_t *tree, PDWORD value)
{
    if (!tree) return NULL;

    itreenode_t *temp = tree;

    // value >= temp->AddressOfFunctions && value < temp->AddressOfFunctions + temp->NumberOfFunctions * sizeof(DWORD)
    // if (value == /*(uint32_t)*/temp->AddressOfFunctions) {

    // with this we can find all the accesses made within the AddressOfFunctions array
    // so that we can compute the offset from the base of the array and reverse the computation
    // to be able to compute the `j`
    // if (value >= temp->AddressOfFunctions && value < temp->AddressOfFunctions + temp->NumberOfFunctions * sizeof(DWORD)) {
    if (value == temp->AddressOfNames) {
        // Value found
        return temp;
    }
    else if (/*(uint32_t)*/temp->AddressOfNames < value) {
        if (temp->right) {
            // Search in the right part
            return itree_search_AddressOfNames(temp->right, value);
        }
        else return NULL;
    } else {
        if (temp->left) {
            // Search in the left part
            return itree_search_AddressOfNames(temp->left, value);
        }
        else return NULL;
    }

    return NULL;
}

// itreenode_t *itree_search_ordinals(itreenode_t *tree, PWORD value)
// {
//     if (!tree) return NULL;

//     itreenode_t *temp = tree;

//     // value >= temp->AddressOfFunctions && value < temp->AddressOfFunctions + temp->NumberOfFunctions * sizeof(DWORD)
//     // if (value == /*(uint32_t)*/temp->AddressOfFunctions) {

//     // with this we can find all the accesses made within the AddressOfFunctions array
//     // so that we can compute the offset from the base of the array and reverse the computation
//     // to be able to compute the `j`
//     // if (value >= temp->AddressOfFunctions && value < temp->AddressOfFunctions + temp->NumberOfFunctions * sizeof(DWORD)) {
//     if (value == temp->AddressOfNameOrdinals) {
//         // Value found
//         return temp;
//     }
//     else if (/*(uint32_t)*/temp->AddressOfNameOrdinals < value) {
//         if (temp->right) {
//             // Search in the right part
//             return itree_search_ordinals(temp->right, value);
//         }
//         else return NULL;
//     } else {
//         if (temp->left) {
//             // Search in the left part
//             return itree_search_ordinals(temp->left, value);
//         }
//         else return NULL;
//     }

//     return NULL;
// }

bool itree_dealloc(itreenode_t *tree)
{
    if (!tree) return true;

	itreenode_t *temp = tree;
	itreenode_t *right = tree->right;
	itreenode_t *left = tree->left;
	free(tree->mod_name);
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
    dr_printf("Level: %u , Range: [%d, %d] , Module name: %s , AddressOfFunctions: 0x%X\n", lvl, node->start_addr, node->end_addr, node->mod_name, node->AddressOfFunctions);
    lvl += 1;

	itree_print(node->left);
	itree_print(node->right);

	return;
}

bool itree_verify(itreenode_t *tree) 
{
	if (!tree) return true;

	// well-formed interval: redundant
	if (tree->end_addr <= tree->start_addr) 
    {
        dr_printf("End address less than start address, module=%s\n", tree->mod_name);
        return false;
    }

	// left child contains interval ending beyond the parent interval's start
	if (tree->left && tree->left->AddressOfFunctions >= tree->AddressOfFunctions)
    {
        dr_printf("Second check failed for %s\n\t[%d]\t[%d]\n", tree->mod_name, tree->AddressOfFunctions, tree->left->AddressOfFunctions);
        return false;
    }
	// right child contains interval starting before the parent interval's end
	if (tree->right && tree->right->AddressOfFunctions <= tree->AddressOfFunctions)
    {
        dr_printf("Third check failed for %s\n", tree->mod_name);
        return false;
    }

	return (itree_verify(tree->left) && itree_verify(tree->right));
}