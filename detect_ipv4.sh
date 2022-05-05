#!/bin/bash

REF_ipv4=(9.9.9.9 119.29.29.29 8.8.8.8)

for RSI in "$@"
do
{
	file="./raw_data/ipv4/raw_data_"${RSI:0:1}".txt"
	exec 1> $file
	for ns in $(dig +short akamai.net NS) 
	do 
		dig -4 +short @$ns whoami.akamai.net A
	done
	echo "******"
	dig @$RSI . SOA +norecurse -4
	echo "******"
	dig @$RSI . SOA +norecurse -4 +tcp
	echo "******"
	traceroute $RSI -I 53
	for REF in ${REF_ipv4[@]}
	do
		echo "******"
		dig @$REF . SOA +norecurse
	done
	
}&
done
wait






