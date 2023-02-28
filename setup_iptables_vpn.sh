#!/bin/bash 

#iptables -F FORWARD && iptables -P FORWARD ACCEPT && iptables -A INPUT -s 5.188.203.0/24 -j DROP && iptables -L

HOSTNAME=$1

if [ -z "$LOGNAME" ]; then
    echo "One or more target server names or IP addresses are needed."
    exit 0
fi

whitelist=(
            127.0.0.0/16
            172.17.0.0/16 # containers
            155.230.0.0/16 # school
            192.168.0.0/16 # local private IP for NAT VMs
            216.58.0.0/16 # google
            34.236.0.0/16 # docker hub
            52.1.0.0/16 # docker hub
            54.209.0.0/16 # docker hub
            54.236.0.0/16 # docker
            54.152.0.0/16 # docker
            54.174.0.0/16 # docker
            54.0.0.0/16 # docker
            54.236.0.0/16 # docker
            52.20.0.0/16 # docker
            34.195.0.0/16 # docker
            34.238.0.0/16 # docker
            18.232.0.0/16 # docker registry-1.docker.io
            3.211.0.0/16 # docker auth.docker.io
            52.1.0.0/16 # docker
            52.20.0.0/16 # docker
            107.23.0.0/16 # docker
            54.85.0.0/16 # docker
            18.213.0.0/16 # docker
            52.72.0.0/16 # docker
            3.218.0.0/16 # docker
            52.167.0.0/16 # gitlab
            192.30.0.0/16 # github
            91.189.0.0/16 # us.archive.ubuntu.com, security.ubuntu.com, archive.ubuntu.com, usn.ubuntu.com
            208.100.0.0/16 # lists.centos.org
            82.195.0.0/16 # lists.debian.org
            38.108.68.0/24 # openstack devstack install
            172.65.251.0/24 # gitlab
            15.164.81.0/24 # github
            64.233.188.128/24 # mini kube install
            74.125.204.128/24 # mini kube install
            64.233.187.128/24 # mini kube install
            64.233.189.128/24 # mini kube install
            108.177.97.128/24 # mini kube install
            52.84.166.20/24 # docker.download.com
            113.29.189.165/24 # pip install
            8.36.41.26/24 # linuxhint.com
            #9.47.0.0/16 # IBM
            #9.2.0.0/16 # IBM
            #121.150.0.0/16 # seo chang ho
            #151.101.1.63
            #151.101.65.63
            #151.101.129.63
            #151.101.193.63
            #114.199.196.202 # jang hyun soo room
            #27.35.108.211 #  jang hyun soo room
            #211.39.72.227/16 # jeju temporary
            #14.56.195.167/16 # nam doha
            #220.66.213.244/24 # IT4 building
            #121.65.177.136/24 # IT4 building
            8.8.8.8 
          ) 

#myservers=( bespin )

#for srv in "${myservers[@]}"
for srv # if there is nothing after "for var", bash assumes "in \"$@\""
do

	echo "Processing " $srv "..."

    ssh root@${srv} "iptables -P INPUT ACCEPT"
    ssh root@${srv} "iptables -P FORWARD ACCEPT"
    ssh root@${srv} "iptables -F"

    # loop back 
    ssh root@${srv} "iptables -A INPUT -i lo -j ACCEPT"
    ssh root@${srv} "iptables -A OUTPUT -o lo -j ACCEPT"

    # dns traffic
    ssh root@${srv} "iptables -A OUTPUT -p udp -o eth0 --dport 53 -j ACCEPT"
    ssh root@${srv} "iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT"

    # dhcp traffic
    ssh root@${srv} "iptables -A OUTPUT -p udp -o eth0 --dport 67 -j ACCEPT"
    ssh root@${srv} "iptables -A INPUT -p udp -i eth0 --sport 67 -j ACCEPT"

    #  allow established and related incoming connection
    ssh root@${srv} "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    ssh root@${srv} "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT"

    # allow http, https
    ssh root@${srv} "iptables -A INPUT -p tcp -m multiport --dports 80,9898,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
    ssh root@${srv} "iptables -A OUTPUT -p tcp -m multiport --dports 80,9898,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT"
    ssh root@${srv} "iptables -A INPUT -p tcp -m multiport --dports 9898,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
    ssh root@${srv} "iptables -A OUTPUT -p tcp -m multiport --dports 9898,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT"

    # allow ssh
    ssh root@${srv} "iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
    ssh root@${srv} "iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT"

    # allow elasticsearch
    #ssh root@${srv} "iptables -A INPUT -p tcp --dport 9200 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
    #ssh root@${srv} "iptables -A OUTPUT -p tcp --sport 9200 -m conntrack --ctstate ESTABLISHED -j ACCEPT"

    for friend in "${whitelist[@]}"
    do
        echo ${srv} $friend
        ssh root@${srv} "iptables -A INPUT -s ${friend} -j ACCEPT"
        ssh root@${srv} "iptables -A FORWARD -s ${friend} -j ACCEPT"
    done
    ssh root@${srv} "iptables -A INPUT -j DROP"
    #ssh root@${srv} "iptables -A FORWARD -j DROP"
    ssh root@${srv} "iptables -L"

    echo " "
done
