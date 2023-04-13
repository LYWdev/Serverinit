#우분투 버전 확인하기
lsb_release -a

#고정 패키지 확인 - 업그레이드 과정에서 문제가 발생할 수 있으므로 확인 후 제거해야함.
sudo apt-mark showhold

#고정 패키지 제거
sudo apt-mark unhold 제거할 대상
 

#저장소 패키지목록 업데이트(apt-get 대신 apt를 사용해도 무방하나, apt-get이 좀 더 안정적이라는 얘기가 있습니다.)

sudo apt-get update
#패키지 업그레이드

sudo apt-get full-upgrade
#커널이 업데이트된 경우, 재부팅합니다. (reboot 명령어만 치면, 1~2분 지연 후 재부팅, 아래 명령어는 즉시 재부팅)

sudo systemctl reboot
#불필요한 패키지 자동 제거

sudo apt-get --purge autoremove
#업데이트 관리자 설치(대부분 이미 설치 되어 있음)

sudo apt-get install update-manager-core
#업그레이드 소스 리스트 변경( /etc/apt/sources.list)

#1) 소스파일 내용 확인(sour정도까지 치고 TAB키를 누르면 자동 완성된다.)
cat /etc/apt/sources.list

#2) 18.04에서 20.04로 업그레이드 하는 경우이므로, bionic을 focal로 바꾸는 명령어를 실행한다.
sudo sed -i 's/bionic/focal/g' /etc/apt/sources.list

#위 방향키를 눌러 이전 1)의 명령어가 나오게 한 후, 엔터. bionic이 focal로 바뀌었음을 확인한다.
#우분투 배포판 업그레이드 - 여기서부터 본격적인 업그레이드 작업입니다.
sudo do-release-upgrade