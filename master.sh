!/bin/bash

# 1. 모든 사용자가 kube 명령어를 사용할 수 있게 하기 위해 다음을 설정한다.
kubeadm init

# Pod 간의 네트워크 통신 위해 다음 명령을 통해 써드파티 애드온인 Weave Net works 설치 수행한다. 
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
