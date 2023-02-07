#!/bin/bash
# Update the apt package index and install packages to allow apt to use a repository over HTTPS:
sudo apt-get update
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# 2.Add Docker’s official GPG key:

sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# 3.Use the following command to set up the repository:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo chmod a+r /etc/apt/keyrings/docker.gpg
sudo apt-get update

sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin


# 4. docker start on boot auto// version check
systemctl enable docekr 
systemctl start docekr 

docker version
## Install k8s
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

#kubectl, kubelet, kubeadm 설치
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl

#Down GCP key
sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg

#add k8s repo
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list

#install k8s kubelet, kubeadm, kubectl
sudo apt-get update
sudo apt-get install -y kubelet 
sudo apt-get install -y kubeadm
sudo apt-get install -y kubectl
sudo apt-mark hold kubelet kubeadm kubectl
#k8s service 등록
sudo systemctl daemon-reload
sudo systemctl restart kubelet
# Master(only)
#kubeadm init

# Pod network 애드온 설치 (master only)
kubectl apply -f https://github.com/weaveworks/weave/releases/download/v2.8.1/weave-daemonset-k8s.yaml