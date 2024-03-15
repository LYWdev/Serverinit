#!/bin/bash

SPL_COUNT=10
SPL_SEED_NETWORK="192.168.10."
SPL_SEED_NETWORK_FULL="192.168.10.100"
VM_START_FROM="2"
SEED="sparklord_seed"
VM_NAME="VM"

mkdir -p virt_clone

seed_state=$(virsh list --all | grep $SEED | awk '{print $3 $4}')
if [ "$seed_state" != "shutoff" ]; then
	virsh shutdown $SEED
	seed_state=$(virsh list --all | grep $SEED | awk '{print $3 $4}')

	while [ "$seed_state" != "shutoff" ]; do
		sleep 1s
		seed_state=$(virsh list --all | grep $SEED | awk '{print $3 $4}')
	done
fi

deploy_vm(){
	vm_name=$1
	ip=$2

	virt-clone --original $SEED --name $vm_name --file ~/virt_clone/$vm_name.qcow2
	virsh start $vm_name

	echo waiting for start ssh server
	ssh root@${SPL_SEED_NETWORK_FULL} "echo a" > /dev/null 2>&1
	while [ $? -ne 0 ]
	do
		sleep 1s
		ssh root@${SPL_SEED_NETWORK_FULL} "echo a" > /dev/null 2>&1
	done

	echo setting $vm_name vm ip $ip
	ssh root@${SPL_SEED_NETWORK_FULL} "cat /etc/netplan/00-installer-config.yaml | yq e '.network.ethernets.enp1s0.addresses[0] = \"$ip/24\"' >00-installer-config.yaml && cp 00-installer-config.yaml /etc/netplan/00-installer-config.yaml && rm 00-installer-config.yaml"

	timeout 5s ssh root@${SPL_SEED_NETWORK_FULL} "netplan apply"
}

# TODO: Add host key to seed vm
echo deploy vm
for (( spl_idx=0; spl_idx<$SPL_COUNT; spl_idx++ )); do
	echo start $spl_idx
	new_ip="${SPL_SEED_NETWORK}$(( $VM_START_FROM + $spl_idx ))"
	if [ $? -eq 0 ]; then
		continue
	fi

	deploy_vm ${VM_NAME}$spl_idx $new_ip

	#ssh-keyscan -t rsa $new_ip >> ~/.ssh/known_hosts

done
