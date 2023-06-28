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

#worker node 아래가 들어가면 오류가 발생함
mv /etc/containerd/config.toml /etc/containerd/config_orient.toml
sudo systemctl restart containerd

sleep 1
echo **********systemctl restart containerd**********

kubeadm join 192.168.30.2:6443 --token hfvw2b.xh0hahx9cg4ibxpb \
        --discovery-token-ca-cert-hash sha256:db8a95246d264c08e4d26d6c316ede22323c5678831eba39bbf8e952bd58eef3

#kata container 설치
sudo apt update
sudo apt install snapd

sudo snap install kata-containers --classic

sudo mkdir -p /etc/kata-containers
sudo cp /snap/kata-containers/current/usr/share/defaults/kata-containers/configuration.toml /etc/kata-containers/
sudo ln -sf /snap/kata-containers/current/usr/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2

export PATH=$PATH:/snap/kata-containers/current/usr/bin

sleep 1
echo **********kata containerd installed**********

sudo cat <<EOF > /etc/containerd/config.toml
disabled_plugins = []
imports = []
oom_score = 0
plugin_dir = ""
required_plugins = []
root = "/var/lib/containerd"
state = "/run/containerd"
version = 2
[plugins]
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
    runtime_type = "io.containerd.runsc.v1"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
         runtime_type = "io.containerd.kata.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
      base_runtime_spec = ""
      container_annotations = []
      pod_annotations = []
      privileged_without_host_devices = false
      runtime_engine = ""
      runtime_root = ""
      runtime_type = "io.containerd.runc.v2"
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
        BinaryName = ""
        CriuImagePath = ""
        CriuPath = ""
        CriuWorkPath = ""
        IoGid = 0
        IoUid = 0
        NoNewKeyring = false
        NoPivotRoot = false
        Root = ""
        ShimCgroup = ""
        SystemdCgroup = true
EOF

sudo systemctl restart containerd

sleep 1
echo **********kata config edited**********

#gvisor 설치

sudo apt-get update && \
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg

(
  set -e
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  wget ${URL}/runsc ${URL}/runsc.sha512 \
    ${URL}/containerd-shim-runsc-v1 ${URL}/containerd-shim-runsc-v1.sha512
  sha512sum -c runsc.sha512 \
    -c containerd-shim-runsc-v1.sha512
  rm -f *.sha512
  chmod a+rx runsc containerd-shim-runsc-v1
  sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin
)

sudo apt-get update && \
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg

curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null

sudo apt-get update && sudo apt-get install -y runsc

sleep 1
echo **********gvisor containerd installed**********

sudo cat <<EOF > /etc/containerd/config.toml
disabled_plugins = []
imports = []
oom_score = 0
plugin_dir = ""
required_plugins = []
root = "/var/lib/containerd"
state = "/run/containerd"
version = 2
[plugins]
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
    runtime_type = "io.containerd.runsc.v1"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
         runtime_type = "io.containerd.kata.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
      base_runtime_spec = ""
      container_annotations = []
      pod_annotations = []
      privileged_without_host_devices = false
      runtime_engine = ""
      runtime_root = ""
      runtime_type = "io.containerd.runc.v2"
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
        BinaryName = ""
        CriuImagePath = ""
        CriuPath = ""
        CriuWorkPath = ""
        IoGid = 0
        IoUid = 0
        NoNewKeyring = false
        NoPivotRoot = false
        Root = ""
        ShimCgroup = ""
        SystemdCgroup = true
EOF

sudo systemctl restart containerd

sleep 1
echo **********gvisor config edited**********