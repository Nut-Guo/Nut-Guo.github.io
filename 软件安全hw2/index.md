# 软件安全hw2


# 软件安全hw2

首先利用checksec进行检查

```
/run/.../SoftwareSecurity/hw2 >>> checksec sample           
[!] Did not find any GOT entries
[*] '/run/media/sciver/Data/Chores/homework/SoftwareSecurity/hw2/sample'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    Packer:   Packed with UPX
```

发现该文件使用了UPX壳。

利用`upx`脱壳。

```
/run/.../SoftwareSecurity/hw2 >>> upx -d sample -o backdoor                    
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX git-d7ba31+ Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     10432 <-      6560   62.88%   linux/amd64   backdoor

Unpacked 1 file.
```

利用ghidra分析程序。通过entry中`__libc_start_main`的第一个参数定位到main函数的地址`0xcb0`。

```C
undefined8 FUN_00100cb0(undefined8 param_1,char **param_2)
{
  int iVar1;
  __uid_t _Var2;
  __uid_t _Var3;
  __gid_t __gid;
  char *pcVar4;
  
  FUN_00100af0(&DAT_003020c0,8);
  pcVar4 = getenv(&DAT_003020c0);
  if ((pcVar4 == (char *)0x0) || (iVar1 = FUN_00100b34(), iVar1 != 0)) {
    _Var2 = geteuid();
    _Var3 = getuid();
    if (_Var2 != _Var3) {
      while( true ) {
        __gid = getgid();
        iVar1 = setgid(__gid);
        if (iVar1 == 0) break;
        sleep(1);
      }
      while( true ) {
        _Var2 = getuid();
        iVar1 = setuid(_Var2);
        if (iVar1 == 0) break;
        sleep(1);
      }
    }
    FUN_00100af0(s_"$)&)_003020b8,6);
    execvp(s_"$)&)_003020b8,param_2);
  }
  else {
    FUN_00100af0(s_`-&!`<'_003020b0,7);
    while (iVar1 = setuid(0), iVar1 != 0) {
      sleep(1);
    }
    execlp(s_`-&!`<'_003020b0,s_`-&!`<'_003020b0,0);
  }
  return 1;
}
```

其中存在大量的含义不明的字符串，推测其内容经过加密。在将其作为参数传递给函数前都利用`FUN_00100af0`进行了处理，推测`FUN_00100af0`为解密函数。

```c
void FUN_00100af0(long param_1,long param_2)

{
  long lVar1;
  long local_18;
  
  local_18 = param_2;
  while (lVar1 = local_18 + -1, local_18 != 0) {
    *(byte *)(lVar1 + param_1) = *(byte *)(lVar1 + param_1) ^ 0x4f;
    local_18 = lVar1;
  }
  return;
}
```

此处采用了明显的异或加密。利用python写出对应的解密脚本。

```python
def xor4f(buf):
    return b''.join([struct.pack("1B",i  ^ 0x4f) for i in buf])
```

利用`rizin`从程序中dump出加密后的字符串的内容，解密后得到明文。

```
[0x000009c0]> pcp 8 @0x2020b0
import struct
buf = struct.pack ("8B", *[
0x60,0x2d,0x26,0x21,0x60,0x3c,0x27,0x00])
[0x000009c0]> pcp 8 @0x2020b8
import struct
buf = struct.pack ("8B", *[
0x22,0x24,0x29,0x26,0x29,0x20,0x00,0x00])
[0x000009c0]> pcp 8 @0x2020c0
import struct
buf = struct.pack ("8B", *[
0x1c,0x07,0x10,0x0c,0x00,0x03,0x00,0x1d])
[0x000009c0]> pcp 8 @0x2020a8
import struct
buf = struct.pack ("8B", *[
0x3f,0x2e,0x3f,0x20,0x2c,0x00,0x00,0x00])
[0x000009c0]> pcp 32 @0x1640
import struct
buf = struct.pack ("32B", *[
0x39,0xf2,0x7e,0xec,0x75,0x58,0xd1,0xca,0x14,0xde,0x3c,
0x58,0x39,0xe8,0x8b,0xab,0xcf,0x26,0xd5,0x15,0x73,0xae,
0x16,0xd0,0x21,0x89,0x5f,0x98,0x22,0x05,0x15,0xec])
```

```python
/run/.../SoftwareSecurity/hw2 >>> ipython                                                                                                                                  
Python 3.9.4 (default, Apr 20 2021, 15:51:38) 
Type 'copyright', 'credits' or 'license' for more information
IPython 7.22.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: def xor4f(buf):
   ...:     return b''.join([struct.pack("1B",i  ^ 0x4f) for i in buf])
   ...: 

In [2]: import struct
   ...: buf640 = struct.pack ("32B", *[
   ...: 0x39,0xf2,0x7e,0xec,0x75,0x58,0xd1,0xca,0x14,0xde,0x3c,
   ...: 0x58,0x39,0xe8,0x8b,0xab,0xcf,0x26,0xd5,0x15,0x73,0xae,
   ...: 0x16,0xd0,0x21,0x89,0x5f,0x98,0x22,0x05,0x15,0xec])
   ...: 
   ...: buf20b0 = struct.pack ("8B", *[
   ...: 0x60,0x2d,0x26,0x21,0x60,0x3c,0x27,0x00])
   ...: buf20b8 = struct.pack ("8B", *[
   ...: 0x22,0x24,0x29,0x26,0x29,0x20,0x00,0x00])
   ...: buf20c0 = struct.pack ("8B", *[
   ...: 0x1c,0x07,0x10,0x0c,0x00,0x03,0x00,0x1d])
   ...: buf20a8 = struct.pack ("8B", *[
   ...: 0x3f,0x2e,0x3f,0x20,0x2c,0x00,0x00,0x00])

In [3]: l = [buf20b0, buf20b8, buf20c0, buf20a8]

In [4]: for b in l:
   ...:     print(xor4f(b))
   ...: 
b'/bin/shO'
b'mkfifoOO'
b'SH_COLOR'
b'papocOOO'
```

结合这一分析结果回顾main函数逻辑，可知其首先读取环境变量`SH_COLOR`的值，其后存在两条路径，第一条路径执行`mkfifo`，第二条路径执行`/bin/sh`。为了利用该后门，显然我们需要找到一种输出使其执行第二条路径。

分支前执行了检查

```c
if ((pcVar4 == (char *)0x0) || (iVar1 = FUN_00100b34(), iVar1 != 0))
```

我们需要使得该条件不成立，即首先环境变量`SH_COLOR`的值不为空，然后函数`FUN_00100b34()`的返回值为0.

```c
bool FUN_00100b34(char *param_1)

{
  int iVar1;
  size_t sVar2;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined local_88 [116];
  int local_14;
  long local_10;
  
  sVar2 = strlen(param_1);
  local_14 = (int)sVar2;
  strncpy((char *)&local_a8,param_1,0x20);
  local_10 = 0;
  while (local_10 < 1) {
    FUN_00101145(local_88);
    FUN_001011bf(local_88,&local_a8,(long)local_14,&local_a8);
    FUN_00100af0(s_?.?_,_003020a8,5);
    FUN_001011bf(local_88,s_?.?_,_003020a8,5);
    FUN_0010125b(local_88,&local_c8,&local_c8);
    local_a8 = local_c8;
    local_a0 = local_c0;
    local_98 = local_b8;
    local_90 = local_b0;
    local_14 = 0x20;
    local_10 = local_10 + 1;
  }
  iVar1 = memcmp(&local_a8,&DAT_00101640,0x20);
  return iVar1 != 0;
}
```

结合上面解密得到的字符串明文，我们看到在该函数最后执行了memcmp，将执行一系列操作之后的字符串与从`0x1640`开始的32个字节，进行比较。

```
[0x000009c0]> s 0x1640
[0x00001640]> p8 0x20
39f27eec7558d1ca14de3c5839e88babcf26d51573ae16d021895f98220515ec
```

我们注意到函数`FUN_00101145()`的内容，

```c
void FUN_00101145(long param_1)

{
  *(undefined4 *)(param_1 + 0x40) = 0;
  *(undefined8 *)(param_1 + 0x48) = 0;
  *(undefined4 *)(param_1 + 0x50) = 0x6a09e667;
  *(undefined4 *)(param_1 + 0x54) = 0xbb67ae85;
  *(undefined4 *)(param_1 + 0x58) = 0x3c6ef372;
  *(undefined4 *)(param_1 + 0x5c) = 0xa54ff53a;
  *(undefined4 *)(param_1 + 0x60) = 0x510e527f;
  *(undefined4 *)(param_1 + 100) = 0x9b05688c;
  *(undefined4 *)(param_1 + 0x68) = 0x1f83d9ab;
  *(undefined4 *)(param_1 + 0x6c) = 0x5be0cd19;
  return;
}
```

向内存中放入了一段特殊的数据。我们在google中搜索`0x6a09e667`得到大量与sha256相关的词条，推测这里使用了sha256求hash，而最终用于比较的长度为32字节的字符串也符合我们的这一猜测。

![](hw2/Screenshot_20210511_135734.png)

hash算法并不可逆，不能手动写逆变换求解，采用彩虹表进行攻击。

![](hw2/Screenshot_20210511_135919.png)

得到结果`000000149100020803781papoc`。

这里的papoc与我们解密的`buf20a8`的值一致，分析`FUN_001011bf`函数，其作用为将两个字符串进行拼接。

综上所述，我们需要将`000000149100020803781`作为环境变量`SH_COLOR`，即可成功触发backdoor。

由于程序在执行过程中需要进行`setuid(0)`的操作需要权限，我们将其变成一个setuid程序后执行，最终成功拿到rootshell。

```python
from pwn import *
name = '/home/sciver/Desktop/sample'
env = {"SH_COLOR":"000000149100020803781"} 
'''
cracked with rainbow table from "39f27eec7558d1ca14de3c5839e88babcf26d51573ae16d021895f98220515ec"

[0x00001640]> p8 0x20
39f27eec7558d1ca14de3c5839e88babcf26d51573ae16d021895f98220515ec

reference:https://anee.me/backdoor-reverse-affinity-ctf-2019-6fb37dc20563
'''
elf = ELF(name)
p = elf.process(env = env)
p.interactive()
```

![](hw2/Screenshot_20210511_141112.png)
