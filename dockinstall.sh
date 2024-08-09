#!/bin/bash

# Docker 설치 스크립트

# 스크립트는 root 권한으로 실행해야 합니다.
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# 1. 기존 Docker 패키지 제거
echo "Removing older versions of Docker, if any..."
apt-get remove -y docker docker-engine docker.io containerd runc

# 2. 패키지 업데이트 및 필요한 패키지 설치
echo "Updating packages..."
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl software-properties-common

# 3. Docker의 공식 GPG 키 추가
echo "Adding Docker's official GPG key..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# 4. Docker의 APT 저장소 추가
echo "Adding Docker's APT repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 5. Docker 설치
echo "Installing Docker..."
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io

# 6. Docker 서비스 시작 및 부팅 시 자동 시작 설정
echo "Starting Docker service..."
systemctl start docker
systemctl enable docker

# 7. 설치 확인
echo "Verifying Docker installation..."
docker --version

echo "Docker installation completed successfully."
