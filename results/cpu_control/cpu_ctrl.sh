#!/bin/bash

read -p "Enter starting core no. : " sc
read -p "Enter ending core no. : " ec
read -p "Enter 0 to turn off, 1 to turn on : " val
i=$sc
while [[ i -le $ec ]]
do
echo $val > /sys/devices/system/cpu/cpu"$i"/online
if [[ $val -eq 0 ]]
then
echo core$i turned off
else
echo core$i turned on
fi
let i=i+1
done
