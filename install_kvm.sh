#!/bin/bash

sudo apt install -y qemu qemu-kvm libvirt-daemon libvirt-clients bridge-utils virt-manager

echo "check status

sudo systemctl status libvirtd
#부팅 시 시작 
sudo systemctl enable --now libvirtd
