!/bin/bash


#  kubeadm은 k8s 관리 운영하는 명령어
#  kubelet은 데몬, 쿠버네티스 컨테이너와 파드를 실행, 컨테이너 조작 및 마스터와 통신할 때 사용
#  kubeclt은 k8s명령어 사용(ex : 컨테이너 실행 등)

# 쿠버네티스 설치를 진행하기위해 저장소 업데이트 및 필수 패키지 추가한다.

sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl

# 쿠버네티스를 설치하기 위해 Kubernetes 저장소 추가한다. 
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list

#저장소 업데이트 후 kubelet, kubeadm, kubectl 설치를 순차적으로 진행한다. 

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# 쿠버네티스를 서비스 등록 및 재시작을 수행한다. 

sudo systemctl daemon-reload
sudo systemctl restart kubelet