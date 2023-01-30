!/bin/bash

# 1.Swap disabled
swapoff -a && sed -i '/swap/s/^/#/' /etc/fstab

# 2.iptable 설정하기 위해 다음 명령을 수행한다. 
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
br_netfilter
EOF
 
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sudo sysctl --system

# 3. 통신을 위해 방화벽 예외 설정을 수행한다. (일반적으로 프라이빗 클라우드는 방화벽끈다.(당연하다 외부에서 들어올 수 없다.))
sudo systemctl stop firewalld
sudo systemctl disable firewalld

#<Ref>
#https://confluence.curvc.com/pages/releaseview.action?pageId=98048155