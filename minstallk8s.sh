#!/bin/bash
#패키지 설치전 업데이트
#Repository 추가


#echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
#curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
#sudo apt-get update && sudo apt-get install -y apt-transport-https
#curl -4 -s https://dl.k8s.io/apt/doc/apt-key.gpg | sudo apt-key add -
#sudo touch /etc/apt/sources.list.d/kubernetes.list
#echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
#sudo apt-get update

#필수 패키지 설치
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
sleep 1
echo **********package installed**********

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo **********NOW : ADD REPO**********

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo **********END : ADD REPO**********
echo **********INSTALL : CONTAINER D, DOCKER  **********

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


echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -

#echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo curl -fsSLo /etc/apt/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg

curl -Ls "https://sbom.k8s.io/$(curl -Ls https://dl.k8s.io/release/stable.txt)/release" | grep "SPDXID: SPDXRef-Package-registry.k8s.io" |  grep -v sha256 | cut -d- -f3- | sed 's/-/\//' | sed 's/-v1/:v1/'

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

sleep 1

mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

sleep 1
echo **********kubeadm init success**********

#kubectl apply -f https://github.com/weaveworks/weave/releases/download/v2.8.1/weave-daemonset-k8s.yaml
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"


sleep 1
echo **********network success**********
