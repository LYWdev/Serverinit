!/bin/bash

##sudo apt-get install upgrade 
echo 'Installing ssh, vim, wget, zip, unzip, curl nettools'
echo 'hello SHS'
echo 'Installing ssh, vim, wget, zip, unzip, curl nettools'
sudo apt-get install -y build-essential libncurses5 libncurses5-dev bin86 kernel-package libssl-dev bison flex libelf-dev
sudo apt-get install -y openssh-server
sudo apt-get install -y vim
sudo apt-get install -y wget
sudo apt-get install -y xrdp
sudo apt-get install -y zip
sudo apt-get install -y unzip
sudo apt-get install -y curl 
sudo apt-get install -y xscreensaver
sudo apt-get install -y net-tools
sudo apt-get install -y ca-certificates
sudo apt-get install -y gnupg
sudo apt-get install -y lsb-release
sudo apt-get install -y kubelet 
sudo apt-get install -y kubeadm
sudo apt-get install -y kubectl
sudo apt-get install -y ufw

#kvm
sudo apt-get install -y cpu-checker
sudo apt install tigervnc-standalone-server tigervnc-xorg-extension tigervnc-viewer

#sudo apt-mark hold kubelet kubeadm kubectl


#echo 'openssh'

sudo system enable ssh
sudo system start ssh

sudo ufw status
sudo ufw status
echo 'ufw status activate'
sudo ufw enable

echo 'install docker'

echo 'sudo apt-get install update'
sudo apt-get install update 

#echo 'Remember to install 
#-> RabbitMQ 
#-> Unity Launcher Folders 
#-> Linux Intel Graphics'

sudo ufw allow 2379:2380/tcp
sudo ufw allow 10250/tcp
sudo ufw allow 10251/tcp
sudo ufw allow 10252/tcp
sudo ufw allow 10255/tcp
sudo ufw allow 6443/tcp
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp

echo 'Screen Saver Off'
gsettings set org.gnome.desktop.screensaver lock-enabled false
gsettings set org.gnome.desktop.screensaver lock-enabled false

#echo 'VM Console service enable'
#systemctl enable serial-getty@ttyS0.service
#systemctl start serial-getty@ttyS0.service
#systemctl status serial-getty@ttyS0.service

#echo 'check status'
sudo ufw enable
sudo ufw status
sudo systemctl status ufw
