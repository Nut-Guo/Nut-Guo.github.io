# 在Manjaro下运行一个Ubuntu


# 在Manjaro下运行一个Ubuntu

在物理机上安装了两个Linux发行版，以应对不同的应用需求，但相互切换频繁操作繁琐，于是开始折腾如何在已经启动一个Linux安装之后使用安装在另一个分区的Linux发行版。

## 1 方案一：修改fstab挂载分区

直接打开Manjaro后，在文件管理器中可以直接打开Ubuntu所在的分区，但是由于每次动态挂载回导致路径不固定，不方便于后续的折腾。可在/etc/fstab文件中添加对于Ubuntu所在分区的挂载，将其挂载到固定的位置。

使用`lsblk -f`命令找到相应分区的UUID，在/etc/fstab文件中添加挂载的配置条目。

```
UUID=<UUID> 	/ubuntu      ext4    defaults,noatime 0 1
```

挂载后，部分软件已经可以直接使用了，例如基于Java的Vivado，在挂载之后可以直接在其安装目录下运行命令，打开图形界面进行使用。但这是因为Vivado是跑在Java虚拟机中的，本机安装了Java之后不需要额外的依赖环境。尝试执行ELF格式的软件时，将会发现部分软件缺少依赖的动态库而无法直接运行，这时仅挂载目录的方案就不能完全解决问题了。

## 2 方案二：mount+chroot

将主机的`/proc`目录`/sys`目录`/run/udev`目录`/dev`目录绑定到Ubuntu文件系统的相应位置，注意由于这些目录均为虚拟文件目录，不必担心这样的绑定破坏了Ubuntu文件系统的完整性。

```bash
mount -t proc /proc /ubuntu/proc
mount --rbind /dev /ubuntu/dev
mount --bind /run /ubuntu/run
mount --bind /tmp /ubuntu/tmp
```

在host操作系统中打开一个新的Xserver并监听，注意需要先使用xhost允许来自localhost的连接。

```bash
sudo xhost +local:
sudo X -quiet -nolisten tcp  -noreset :1 vt2
```

chroot到Ubuntu操作系统中之后指定使用的DISPLAY端口，即可在相应的tty中执行GUI应用程序。

例如：`DISPLAY=:1 firefox`。或者也可以直接指定`DISPLAY=:0`，使用主机的桌面环境。

这一方法可以支撑ELF格式的软件的执行，但问题在于可能没有办法使用网络。

## 3 方案三：systemd-nspawn

直接使用`systemd-nspawn`指令，可用于在一个轻量命名空间容器中运行命令或操作系统。它比 [chroot](https://wiki.archlinux.org/index.php/Chroot) 更强大在于它完全虚拟化了文件系统层次结构、进程树、各种 IPC 子系统以及主机和域名。

通过该指令可直接在container中运行一个受限的Ubuntu操作系统，通过systemd-nspawn，可以直接在另一个tty中打开一个ubuntu的gnome桌面。

将操作封装为函数添加到`.zshrc`以便重用。

```bash
function spawn_ubuntu() {
  sudo xhost +local:
  sudo X -quiet -nolisten tcp  -noreset :1 vt2 >> /dev/null 2>&1 &#打开Xserver
  sudo systemd-nspawn -bD /ubuntu \
    --bind=/lib/modules \
    --bind-ro=/tmp/.X11-unix \
    --bind=/mnt #非必要
}
```

在终端中直接输入spawn_ubuntu便可直接使用Ubuntu了，终端中登录后使用

```bash
DISPLAY=:1 gnome-session
```

在tty2中打开gnome桌面环境，通过`Ctrl + Alt + <tty_num>`在不同的tty之间进行切换。

## 参考文献

[fstab wiki](https://wiki.archlinux.org/index.php/Fstab)

[ Chroot with second desktop environment - Howto and notes](https://www.linuxquestions.org/questions/linux-from-scratch-13/chroot-with-second-desktop-environment-howto-and-notes-4175614913/)

[systemd-nspawn wiki](https://wiki.archlinux.org/index.php/Systemd-nspawn)
