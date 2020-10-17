# 内核调试环境配置


# 操作系统实验环境配置

操作系统实验中，利用qemu运行RISCV架构下的操作系统，gdb远程调试。利用vscode给gdb提供图形界面的支持可以极大的改善调试体验。

## 1 安装Native Debug插件

![Native Debug](Kernel_Debug/Native_Debug.png "Native Debug")

## 2 配置Lauch.json

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "gdb",
            "request": "attach",
            "name": "Attach to QEMU",
            //替换为自己的可执行文件路径
            "executable": "${workspaceFolder}/prj2/main", 
            //将端口替换为当前实验中qemu打开的端口，例如xv6习惯于使用26000
            "target": "localhost:1234",
            "remote": true,
            "cwd": "${workspaceRoot}", 
            //替换为相应的gdb可执行文件的地址
            "gdbpath": "/riscv64-linux/bin/riscv64-unknown-linux-gnu-gdb", 
            "autorun": [
                //添加其他需要的文件提供调试信息
                "add-symbol-file ${workspaceFolder}/prj2/bootblock",
                //在入口函数下断点
                "b _start" 											
            ]
        },
    ]
}
```

## 3 愉快调试

在终端中启动qemu后，`F5`打开调试器，程序将自动停止在设定的断点处。
![debug](Kernel_Debug/debug.png "debug")

Tips:
1. 使用侧边栏调试窗口中的Call Stack查看调用栈
2. Debug Console中照常使用gdb打印信息
3. 在.gdbinit中自定义宏，打印信息,例如:
```sh
define plist
    set $hd = (list_node_t*)&ready_queue
    set $nd = ready_queue->next
    while($nd != $hd)
        p/x $nd
        set $nd = ((list_node_t*)$nd)->next
    end
end

define pcur
    printf "current_running->kernel_sp= %lx",current_running->kernel_sp
    printf "current_running->user_sp= %lx",current_running->user_sp
    printf "context:\n"
    x/36gx current_running->kernel_sp
end
```
示例：
![pcur](Kernel_Debug/pcur.png "pcur")

祝大家调试愉快。
