#!/bin/bash 

db_file="14e5.csdb"

kw_list=""
kKeywordGroupBase="Group-"
kKeyword10GroupBase=$kKeywordGroupBase"10^"


for i in `seq 0 7`;
do
	for j in `seq 0 7`; #total number is 1000
	do
		kw_list=$kw_list" "$kKeyword10GroupBase"1_"$i"_"$j
	done
done

./client -b $db_file $kw_list

