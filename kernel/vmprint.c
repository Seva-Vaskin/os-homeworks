#include "types.h"
#include "riscv.h"
#include "defs.h"

void vmprint_recursive(pagetable_t pagetable, int depth) {
    for(int i = 0; i < 512; i++){
        pte_t pte = pagetable[i];

        uint64 pa = PTE2PA(pte);
        if (pte & PTE_V) {
            for (int i = 0; i < depth; i++) {
                printf(" ..");
            }
            printf("%d: pte %p pa %p\n", i, pte, pa);
        }
        if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
            // this PTE points to a lower-level page table.
            uint64 child = PTE2PA(pte);
            vmprint_recursive((pagetable_t)child, depth + 1);
        }
    }
}

void
vmprint(pagetable_t pagetable) {
    printf("page table %p\n", pagetable);
    vmprint_recursive(pagetable, 1);
}