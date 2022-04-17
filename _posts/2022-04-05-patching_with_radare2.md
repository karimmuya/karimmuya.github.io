---
layout: post
title: "Patching x86 Binaries using  Radare 2"
description: "Binary patching is the process of modifying a compiled executable to change its execution flow."
tags: [ctf, reverse_engineering]
---



In this example we will be using a binary from picoCTF 2022 ```bbbbloat```, a reverse engineering challenge.

Let's take a look at the binary:
```s
[karim@karim ]$ file bbbbloat 
bbbbloat: ELF 64-bit LSB pie executable, x86-64,
```
<br />
So we are just given a ```64 bit``` Linux executable

```s
[karim@karim ]$ ./bbbbloat 
Whats my favorite number? 2
Sorry, thats not it!
```
<br />

When we run it, we see that it prompts us for a correct number to get the flag but we dont know that number, so our goal here is to patch the binary and get the flag even without knowing the correct number.

When we look at it in Radare and analyse the main function we see these set instruction that can be of interest to us:
```s
      0x000014cb      3d87610800     cmp eax, 0x86187
  ┌─< 0x000014d0      0f85ad000000   jne 0x1583
  │   0x000014d6      c745c4783000.  mov dword [var_3ch], 0x3078 ; 'x0'

```
<br />

The ```jne  0x1583``` instruction indicates that the execution will ```jump``` to address ```0x1583``` if the result after comparison between ```eax``` and ```0x86187``` is not equal, ```jne``` is just a different name for a conditional jump when ```ZF``` is equal to ```0```.

As long as the number is not correct the ```cmp eax, 0x86187``` check will always not be equal and the ```jne``` instruction will redirect execution to the address ```0x86187``` which prints the message ```Sorry, that's not it!``` and exits the program, So the plan here is to change the ```jne```  to ```je``` to bypass the error message and print the flag.

First, let us sym to ```jne  0x1583``` instruction:
```s
[0x000014d0]> s 0x000014d0
[0x000014d0]> pd 1
│       ┌─< 0x000014d0      0f85ad000000   jne 0x1583
[0x000014d0]> 
```

<br />

Then, change ```jne``` to ```je``` using ```wao recj``` command in radare which reverse (swap) conditional branch instruction:
```s
[0x000014d0]> wao recj
[0x000014d0]> pd 1
│       ┌─< 0x000014d0      0f84ad000000   je 0x1583
[0x000014d0]> 

```

<br />

As we can see the the instruction changed form ```jne 0x1583``` to ```je 0x1583```.
Now lets quit Radare and run again the patched binary to see if we have successfully altered code execution:

```s
[karim@karim ]$ ./bbbbloat 
Whats my favorite number? 2
picoCTF{cu7_7h3_bl047_2d7aeca1}

```
<br />

As we can see it prompted us for a number, we wrote the same wrong number but it printed the flag.

<br />

Thats it ...We did it!!!!



