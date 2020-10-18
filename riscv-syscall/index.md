# Riscv Syscall


# RISC-V 特权级切换

UCAS的计算机专业操作系统实验中要求实现sleep系统调用，涉及到RISC-V的一些细节，需要阅读手册理解该指令集下的工作机制，在此做一总结。

## 1 切换运行模式至用户态

实验手册的注意事项中给出了如下提示：

> RISC-V 在所有特全级下都用ecall执行系统调用。Supervisor态ecall会触发machine态的例外，user态的ecall会触发supervisor态的中断。所以大家务必注意，要让USER模式的进程/线程运行在用户态。

Supervisor模式和User模式的切换是后续顺利实验的关键。《RISC-V手册》第10章关于特权架构的介绍中提到：

> S 模式有几个异常处理 CSR:sepc、stvec、scause、sscratch、stval 和 sstatus,它们执行与 M 模式 CSR 相同的功能。监管者异常返回指令 sret 与 mret 的行为相同,但它作用于 S 模式的异常处理 CSR,而不是 M 模式的 CSR。S 模式处理例外的行为已和 M 模式非常相似。如果 hart 接受了异常并且把它委派给了S 模式,则硬件会原子地经历几个类似的状态转换,其中用到了 S 模式而不是 M 模式的CSR:
>
> - 发生例外的指令的 PC 被存入 sepc,且 PC 被设置为 stvec。
> - scause 根据异常类型设置,stval 被设置成出错的地址或者其它特定异常的信息字。
> - 把 sstatus CSR 中的 SIE 置零,屏蔽中断,且 SIE 之前的值被保存在 SPIE 中。
> - 发生例外时的权限模式被保存在 sstatus 的 SPP 域,然后设置当前模式为 S 模式。

这一部分描述了从User模式进入到Supervisor模式的过程中硬件的处理机制，从Supervisor模式返回User模式的过程手册中没有直接介绍，但可以通过对mret的介绍了解其工作方式。

> 处理程序用 mret 指令(M 模式特有的指令)返回。mret 将 PC 设置为 mepc,通过将 mstatus 的 MPIE 域复制到MIE 来恢复之前的中断使能设置,并将权限模式设置为 mstatus 的 MPP 域中的值。
> 这基本是前一段中描述的逆操作。

显然想要将运行模式切换到用户态，需要的指令就是sret了。

在执行sret之前，需要准备好sepc，sstatus寄存器，这一部分寄存器应当在恢复上下文时完成，需要特别关注sstatus的SPIE位以及SPP位，这为初始化PCB时的设计给出了提示。具体实现可通过阅读手册中对于sret指令的说明得到一些提示。

##  2 系统调用

ecall指令我们在Project 1的SBI_CALL中见到过，当时的用法是通过寄存器传参后调用sbi函数，这是在Supervisor模式下的行为。如果读者在没有完成上下文切换的时候尝试过使用ecall指令触发中断，并仔细调试的话，预期触发中断的地方很可能直接执行了一个sbi函数。而若已经正确切换到Supervisor模式，将会跳转到stvec继续执行，异常类型存放在scause中，stval 被设置成出错的地址或者其它特定异常的信息字。后续系统调用的实现就很简单了，不再赘述。

祝大家实验顺利。

## 3 参考文献

[RISC-V 手册](http://crva.ict.ac.cn/documents/RISC-V-Reader-Chinese-v2p1.pdf)

[P2-Guidebook-RISCV]()
