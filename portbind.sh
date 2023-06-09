#!/bin/bash
if [ $# = 0 ]
then
  echo "usage: forwarding.sh in_port out_ip out_port"
  exit 1
fi
in_port=$1
out_ip=$2
out_port=$3
iptables -I INPUT -p tcp -s 155.230.0.0/16 -d 155.230.91.207 --dport $in_port -j ACCEPT
iptables -I FORWARD -m tcp -p tcp -d $out_ip --dport $out_port -j ACCEPT
iptables -I FORWARD -m state -p tcp -d 155.230.0.0/16 --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -I PREROUTING -p tcp -d 155.230.91.207 --dport $in_port -j DNAT --to-destination $out_ip:$out_port
