#!/bin/bash
#패키지 설치전 업데이트

sudo apt-get update

#필수 패키지 설치
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

sleep 1

echo **********package installed**********

#Repository 추가
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
​
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

#Docker, containerd 설치
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

sleep 1
echo **********Docker install finished**********

sudo systemctl enable docker
sudo systemctl start docker

sudo systemctl enable containerd
sudo systemctl start containerd

sudo systemctl daemon-reload
sudo systemctl restart docker

#Swap off 이걸 해야 정상적으로 됨
sudo swapoff -a && sudo sed -i '/swap/s/^/#/' /etc/fstab

#Kubelet, kubeadm, kubectl 설치 (모든 master, worker node)
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
br_netfilter
EOF

cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

sudo sysctl --system

sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl

sleep 1
echo **********apt-get install -y apt-transport-https ca-certificates curl**********

sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg

echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

sleep 1
echo **********apt-mark hold kubelet kubeadm kubectl**********

sudo systemctl daemon-reload
sudo systemctl restart kubelet

sleep 1
echo **********k8s installed completed**********

#master
sudo mv /etc/containerd/config.toml /etc/containerd/config_origin.toml
sudo systemctl restart containerd
sudo kubeadm init

mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

sleep 1
echo **********kubeadm init success**********

kubectl apply -f https://github.com/weaveworks/weave/releases/download/v2.8.1/weave-daemonset-k8s.yaml

sleep 1
echo **********network success**********