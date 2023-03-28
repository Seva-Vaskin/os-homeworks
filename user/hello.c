#include "kernel/types.h"
#include "user/user.h"

int main() {
	
	int ten = hello(2, 5);
	printf("%d\n", ten);
	exit(0);
}
