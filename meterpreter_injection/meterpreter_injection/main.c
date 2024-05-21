#include <stdio.h>
#define NOP1   __asm { nop }
#define NOP2   NOP1  NOP1
#define NOP4   NOP2  NOP2
#define NOP8   NOP4  NOP4
#define NOP16  NOP8  NOP8
#define NOP32  NOP16  NOP16
#define NOP64  NOP32  NOP32
#define NOP128  NOP64  NOP64
#define NOP256  NOP128  NOP128

int somefunc()
{
    __asm
    {
        NOP256
        NOP256
        NOP256
        NOP256
        NOP256
        NOP256
        NOP256
        NOP256
    }
    // Return with result in EAX
}

int main(int argc, char* argv) {
    somefunc();

	return 0;
}
