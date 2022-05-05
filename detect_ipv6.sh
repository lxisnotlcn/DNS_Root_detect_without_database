#!/bin/bash

REF_ipv6=(2620:fe::fe 2402:4e00:: 2001:4860:4860::8888)

for RSI in "$@"
do
{
	file="./raw_data/ipv6/raw_data_"${RSI:0:1}".txt"
	exec 1> $file
	dig -6 TXT +short o-o.myaddr.l.google.com @ns1.google.com
#	for ns in $(dig +short akamai.net NS) 
#	do 
#		dig -6 +short @$ns whoami.akamai.net AAAA
#	done
	echo "******"
	dig @$RSI . SOA +norecurse -6
	echo "******"
	dig @$RSI . SOA +norecurse -6 +tcp
	
	echo "******"
	traceroute -I $RSI -6
	
	for REF in ${REF_ipv6[@]}
	do
		echo "******"
		dig @$REF . SOA +norecurse
	done
	
}&
done
wait






