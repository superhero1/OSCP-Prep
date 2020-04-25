# Install Kali on AWS EC2 Free Tier
*Work in progress by [superhero1](https://twitter.com/_superhero1), watch the stream on [Twitch](https://twitch.tv/sup3rhero1)*

## Launch AWS EC2 Instance

Select "Debian 9", t3.micro. Set Storage to 30GB and uncheck T2/T3 Unlimited.

## Turn Debian into Kali

### Create swap file
```
sudo /bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=2048
sudo /sbin/mkswap /var/swap.1
sudo chmod 600 /var/swap.1
sudo /sbin/swapon /var/swap.1
```

### Change hostname (optional)
```
sudo vi /etc/cloud/templates/hosts.debian.tmpl
sudo hostname kali
```

### Install Kali Linux default

SSH into your EC2 instance and run the following commands:

```
sudo apt-get update && sudo apt-get upgrade -y
sudo passwd
su root
echo "deb http://ftp.halifax.rwth-aachen.de/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
exit
sudo apt-get update && sudo apt-get -y --allow-unauthenticated install kali-archive-keyring && sudo apt-get update
sudo apt-get -y install tmux
tmux
sudo apt-get -y install kali-linux-default
```

For restarting service automatically while Configuring libc6:amd64 select `<Yes>`.

If there is a text displayed, press `q` to exit.

- For Samba server and utilities select `<No>`.
- For Configuring macchanger select `<No>`.
- For wireshark-common select `<No>`.
- For kismet-capture-common select `<Yes>`, in the next window type `admin`.
- For sshl select `standalone`.

For any other questions choose `Keep the local version installed`.

### Full system upgrade
```
sudo apt-get -y update && sudo apt-get -y upgrade && sudo apt-get -y dist-upgrade && sudo apt-get -y autoremove
```

`Keep the local version installed` and for GRUB do not select anything and proceed without installing it.

Configure your time zone: `sudo dpkg-reconfigure tzdata` and reboot `sudo shutdown -r now`.

If you want to skip the system information after login run `touch .hushlogin`.

### Create .bash_aliases (optional)
```
thm(){
sudo openvpn --config /home/admin/.ovpn/superhero1.ovpn --daemon
}
settarget(){
echo $1 | xargs -I {} sudo sed -i 's/10.10.*/{} target/' /etc/hosts
}
alias ll='ls -la'
```

## Install Desktop (not working properly: slow, no window title bars)
```
sudo apt-get -y install kali-desktop-xfce xorg xfce4 xfce4-places-plugin xfce4-goodies
```

Afterwards, run `vncserver` and setup your VNC password, for view-only select `n`.

Edit this file `vi ~/.vnc/xstartup` to match:
```
#!/bin/sh

xrdb $HOME/.Xresources
xsetroot -solid grey
#x-terminal-emulator -geometry 80x24+10+10 -ls -title "$VNCDESKTOP Desktop" &
#x-window-manager &
# Fix to make GNOME work
export XKL_XMODMAP_DISABLE=1
#/etc/X11/Xsession
/usr/bin/xfce4-session
```
Kill the running session `vncserver -kill :1`.

### Forwarding VNC port

`plink -load aws -L 8000:localhost:5901 -N`

### Adjust desktop size

`vncserver -geometry 1920x1080`

## Install some more tools

- SecLists
- ffuf
