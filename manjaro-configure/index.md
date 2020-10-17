# Manjaro


# Configure manjaro

## Change sources

### rank mirrors

```bash
sudo pacman-mirrors -i -c China -m rank
sudo pacman -Syu
```

### change the gem source

```bash
gem sources --add https://mirrors.tuna.tsinghua.edu.cn/rubygems/ --remove https://rubygems.org/
```

## change the npm source 

```bash
npm install -g nrm          // 全局安装nrm模块
nrm ls                      // 显示所有可用的源
nrm use taobao              // 切换到淘宝源：
```

## change the bundle source

```bash
bundle config mirror.https://rubygems.org https://mirrors.tuna.tsinghua.edu.cn/rubygems 
```

### add archlinuxcn and arch4edu

```bash
#edit /etc/pacman.conf
#append the following content
[archlinuxcn]
SigLevel = Optional TrustedOnly
Server = http://mirrors.ustc.edu.cn/archlinuxcn/$arch

[arch4edu]
SigLevel = Never
Server = http://mirrors.tuna.tsinghua.edu.cn/arch4edu/$arch
```

add the archlinuxcn-keyring

```bash
sudo pacman -S archlinuxcn-keyring
sudo pacman -Syu
```

### add blackarch

```bash
# Run https://blackarch.org/strap.sh as root and follow the instructions.
$ curl -O https://blackarch.org/strap.sh

# The SHA1 sum should match: 9f770789df3b7803105e5fbc19212889674cd503 strap.sh
$ sha1sum strap.sh

# Set execute bit
$ chmod +x strap.sh

# Run strap.sh
$ sudo ./strap.sh 

#change the source
#edit the /etc/pacman.conf
[blackarch]
SigLevel = Optional TrustAll
Server = https://mirrors.ustc.edu.cn/blackarch/$repo/os/$arch
# add keyring first
```



## Necessary software

- zsh

  ```bash
  sudo pacman -S manjaro-zsh-config
  chsh -s /bin/zsh
  ```

- yay

  ```bash
  sudo pacman -S yay
  ```

- chrome typora nvim code anaconda goldendict

  ``` bash
  sudo pacman -S google-chrome typora code goldendict
  ```

- rime-pinyin

  ```bash
  sudo pacman -S fctix-rime kcm-fcitx fcitx-gtk2 fcitx-gtk3#need to log out
  ```

- gdb&radare2&pwntools

  ```bash
  sudo pacman -S pwndbg peda gef radare2
  ```

- ghidra

  ```bash
  sudo pacman -S ghidra
  ```

- vmware

  ```bash
  sudo pacman -S vmware-workstation
  ```
  
  Remember to install the right linux-headers before using vmware, and start the networking.
  
  ```bash
  systemctl start vmware-networks.service
  systemctl enable vmware-networks.service
  ```

- metasploit

  ```bash
  sudo pacman -S msfdb metasploit
  ```

## Configure the environment

- asystem time synchronize

  ```bash
  sudo timedatectl set-local-rtc true
  ```

- mount the windows partion

  ```
  UUID=0CB47F55B47F406E                     /mnt/C         ntfs-3g defaults         0 0  UUID=585245C85245AB96                     /mnt/D         ntfs-3g defaults         0 0
  ```


## Backup

[backup with clonezilla](https://forum.manjaro.org/t/full-system-backup/2309/12)

[restore the grub](https://forum.manjaro.org/t/how-to-repair-manjaro-grub-after-it-has-been-restored-from-a-clonezilla-backup-image/84)
