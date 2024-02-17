#!/bin/bash

# MongoDB 공식 GPG 키 추가
wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -

# MongoDB 저장소 추가
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list

# 패키지 목록 업데이트
sudo apt-get update

# MongoDB 설치
sudo apt-get install -y mongodb-org

# MongoDB 서비스 시작
sudo systemctl start mongod

# MongoDB 서비스가 부팅 시 자동으로 시작하도록 설정
sudo systemctl enable mongod
