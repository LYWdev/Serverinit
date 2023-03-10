!/bin/bash

##sudo apt-get install upgrade 
echo 'Installing ssh, vim, wget, zip, unzip, curl nettools'
sudo apt-get install -y ssh
sudo apt-get install -y vim
sudo apt-get install -y wget
sudo apt-get install -y xrdp
sudo apt-get install -y zip
sudo apt-get install -y unzip
sudo apt-get install -y curl 
sudo apt-get install -y xscreensaver
sudo apt-get install -y net-tools

echo 'sudo apt-get install update'
sudo apt-get install update 

echo 'Remember to install 
-> RabbitMQ 
-> Unity Launcher Folders 
-> Linux Intel Graphics'

echo 'Screen Saver Off'
gsettings set org.gnome.desktop.screensaver lock-enabled false
gsettings set org.gnome.desktop.screensaver lock-enabled false

echo 'VM Console service enable'
systemctl enable serial-getty@ttyS0.service
systemctl start serial-getty@ttyS0.service


