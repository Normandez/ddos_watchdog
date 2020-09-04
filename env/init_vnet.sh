#!/bin/bash

# Scheme follows:
#
#               USER SPACE
#
#    (10.8.0.1) ext <--- WATCHDOG --->int (10.8.0.2)
#                ^                  ^
# ...............|........   .......|...................
#                v       :   :      v
# (192.168.1.1) eth      :   :     eth (192.168.2.1)
#                        :   :
#      192.168.1.0/24    :   :     192.168.2.0/24
#      EXTERNAL SPACE    :   :     INTERNAL SPACE
#     

################################## add_netns ##############################################
# This script provides a convenietn way to virtual network space creation with						#
# virtual network interface with specified address and in UP state. RUN WITH SUDO!				#
#																																													#
# USAGE: init_vnet.sh <SUBNET_EXT_NAME> <SUBNET_INT_NAME> <SUBNET_EXT_DEV_NAME>						#
#											<SUBNET_INT_DEV_NAME> <SUBNET_EXT_RT_IP> <SUBNET_INT_RT_IP>					#
#											<SUBNET_INT_IP> <SUBNET_EXT_IP>																			#
#											<SUBNET_INT_GATEWAY> <SUBNET_EXT_GATEWAY>														#
#																																													#
# Input params:																																						#
#		<SUBNET_EXT_NAME> - external network namespace name																		#
#		<SUBNET_INT_NAME> - internal network namespace name																		#
#		<SUBNET_EXT_DEV_NAME> - host's namespace virtual ethernet device name									#
#		<SUBNET_INT_DEV_NAME> - host's namespace virtual ethernet device name									#
#		<SUBNET_EXT_RT_IP> - the IP-address of external subnetwork's router (without mask)		#
#		<SUBNET_INT_RT_IP> - the IP-address of internal subnetwork's router (without mask)		#
#		<SUBNET_INT_IP> - the IP-address of internal subnetwork (with mask)										#
#		<SUBNET_EXT_IP>	-	the IP-address of external subnetwork (with mask)										#
#		<SUBNET_INT_GATEWAY> - default router's IP-adress of internal subnet (without mask)		#
#		<SUBNET_EXT_GATEWAY> - default router's IP-address of external subnet (without mask)	#
#																																													#
#	Exit codes:																																							#
#		0 - all OK																																						#
#		1 - invalid arguments																																	#
#																																													#
###########################################################################################

# Input arguments checking
check_arguments()
{
	readonly local valid_input_args_num=10
	readonly local usage_line="init_vnet.sh <SUBNET_EXT_NAME> <SUBNET_INT_NAME> <SUBNET_EXT_DEV_NAME> <SUBNET_INT_DEV_NAME> <SUBNET_EXT_RT_IP> <SUBNET_INT_RT_IP> <SUBNET_INT_UP> <SUBNET_EXT_IP> <SUBNET_INT_GATEWAY> <SUBNET_EXT_GATEWAY>"
	if [ $1 != $valid_input_args_num ];
	then
		printf "Invalid arguments num: $1\nValid num: ${valid_input_args_num}\nUSAGE: ${usage_line}\n";
		exit 1;
	fi
}

# Virtual network workflow creation/overriding
add_subnets()
{
	# Overriding
	for iface in $(basename -a /sys/class/net/*)
	do
		if [ $iface == ${SUBNET_EXT_DEV_NAME} ]
		then
			ip link del ${iface}
		elif [ $iface == ${SUBNET_INT_DEV_NAME} ]
		then
			ip link del ${iface}
		fi
	done

	for subnet in $(ip netns list)
	do
		if [ $subnet == $SUBNET_EXT_NAME ]
		then
			ip netns del ${SUBNET_EXT_NAME}
		elif [ $subnet == $SUBNET_INT_NAME ]
		then
			ip netns del ${SUBNET_INT_NAME}
		fi
	done
	
	# Creation
	ip netns add ${SUBNET_EXT_NAME}
	ip netns add ${SUBNET_INT_NAME}
	
	ip link add ${SUBNET_EXT_DEV_NAME} type veth peer name ${C_DEFAULT_VETH_DEV_NAME} netns ${SUBNET_EXT_NAME}
	ip link add ${SUBNET_INT_DEV_NAME} type veth peer name ${C_DEFAULT_VETH_DEV_NAME} netns ${SUBNET_INT_NAME}
}

# Address attachment to devices
init_addresses()
{
	# Routers
	ip addr add ${SUBNET_EXT_RT_IP} dev ${SUBNET_EXT_DEV_NAME}
	ip addr add ${SUBNET_INT_RT_IP} dev ${SUBNET_INT_DEV_NAME}

	# Gateways
	ip -n ${SUBNET_EXT_NAME} addr add ${SUBNET_EXT_GATEWAY} dev ${C_DEFAULT_VETH_DEV_NAME}
	ip -n ${SUBNET_INT_NAME} addr add ${SUBNET_INT_GATEWAY} dev ${C_DEFAULT_VETH_DEV_NAME}
}

# Devices startup
up_devices()
{
	# Base
	ip link set ${SUBNET_EXT_DEV_NAME} up
	ip link set ${SUBNET_INT_DEV_NAME} up

	# External
	ip -n ${SUBNET_EXT_NAME} link set ${C_DEFAULT_LOOPBACK_NAME} up
	ip -n ${SUBNET_EXT_NAME} link set ${C_DEFAULT_VETH_DEV_NAME} up

	# Internal
	ip -n ${SUBNET_INT_NAME} link set ${C_DEFAULT_LOOPBACK_NAME} up
	ip -n ${SUBNET_INT_NAME} link set ${C_DEFAULT_VETH_DEV_NAME} up
}

# Creates routing map between subnetworks
add_routes()
{
	# Host-namespace routing
	ip route add ${SUBNET_EXT_IP} via ${SUBNET_EXT_RT_IP} dev ${SUBNET_EXT_DEV_NAME}
	ip route add ${SUBNET_INT_IP} via ${SUBNET_INT_RT_IP} dev ${SUBNET_INT_DEV_NAME}

	# Virtual-namespace routing
	ip -n ${SUBNET_EXT_NAME} route add ${C_DEFAULT_GATEWAY_NAME} via ${SUBNET_EXT_GATEWAY} dev ${C_DEFAULT_VETH_DEV_NAME}
	ip -n ${SUBNET_INT_NAME} route add ${C_DEFAULT_GATEWAY_NAME} via ${SUBNET_INT_GATEWAY} dev ${C_DEFAULT_VETH_DEV_NAME}
}

# Disables hardware offloading for created subnetwork's interfaces
disable_offloading()
{
	for opt in rx tx gso ; do ip netns exec ${SUBNET_EXT_NAME} ethtool -K ${C_DEFAULT_VETH_DEV_NAME} $opt off 1>/dev/null ; done
	for opt in rx tx gso ; do ip netns exec ${SUBNET_INT_NAME} ethtool -K ${C_DEFAULT_VETH_DEV_NAME} $opt off 1>/dev/null ; done
}


##### MAIN #####

# Consts
readonly C_DEFAULT_GATEWAY_NAME="default"
readonly C_DEFAULT_VETH_DEV_NAME="eth"
readonly C_DEFAULT_LOOPBACK_NAME="lo"

check_arguments $#

# Global vars
SUBNET_EXT_NAME=$1
SUBNET_INT_NAME=$2
SUBNET_EXT_DEV_NAME=$3
SUBNET_INT_DEV_NAME=$4
SUBNET_EXT_RT_IP=$5
SUBNET_INT_RT_IP=$6
SUBNET_INT_IP=$7
SUBNET_EXT_IP=$8
SUBNET_INT_GATEWAY=$9
SUBNET_EXT_GATEWAY=${10}

add_subnets
init_addresses
up_devices
add_routes
disable_offloading

exit 0

