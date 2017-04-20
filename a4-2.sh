#! /bin/bash
# Created on Sun Feb 26 12:57:49 CST 2017

for ip in 10.40.40.130 10.40.40.131 10.40.40.132 10.40.40.133 10.40.40.242
do
hostname=$(snmpget -v 2c -c public ${ip} sysName.0 | sed -e 's/^SNMPv2-MIB::sysName.0 = STRING: //g')
echo -e "\nHostname of device:${hostname}"

serial=$(snmpget -v 2c -c public ${ip} 1.3.6.1.2.1.47.1.1.1.1.11.1 | sed -e 's/^ENTITY-MIB::entPhysicalSerialNum.1 = STRING: //g')
echo -e "Serial number of ${hostname}:${serial}"

ifnumber=$(snmpget -v 2c -c public ${ip} ifNumber.0 | sed -e 's/^IF-MIB::ifNumber.0 = INTEGER: //g')
ifname=$(snmpbulkget -v 2c -Cr$ifnumber -c public ${ip} ifDescr | sed -e 's/^IF-MIB::ifDescr.*[0-9] = STRING: //g')
iftype=$(snmpbulkget -v 2c -Cr$ifnumber -c public ${ip} ifType | sed -e 's/^IF-MIB::ifType.*[0-9] = INTEGER: //g' | cut -d "(" -f 1)
ifmac=$(snmpbulkget -v 2c -Cr$ifnumber -c public ${ip} ifPhysAddress | sed -e 's/^IF-MIB::ifPhysAddress.*[0-9] = STRING: //g')
ifoper=$(snmpbulkget -v 2c -Cr$ifnumber -c public ${ip} ifOperStatus | sed -e 's/^IF-MIB::ifOperStatus.*[0-9] = INTEGER: //g' | cut -d "(" -f 1)
ifinUpac=$(snmpbulkget -v 2c -Cr$ifnumber -c public ${ip} ifInUcastPkts | sed -e 's/^IF-MIB::ifInUcastPkts.*[0-9] = Counter32: //g')
ifinNUpac=$(snmpbulkget -v 2c -Cr$ifnumber -c public ${ip} ifInNUcastPkts | sed -e 's/^IF-MIB::ifInNUcastPkts.*[0-9] = Counter32: //g' | sed -e 's/^IF-MIB::ifInDiscards.*[0-9] = Counter32: //g')
ifoutUpac=$(snmpbulkget -v 2c -Cr$ifnumber -c public ${ip} ifOutUcastPkts | sed -e 's/^IF-MIB::ifOutUcastPkts.*[0-9] = Counter32: //g')
ifoutNUpac=$(snmpbulkget -v 2c -Cr$ifnumber -c public ${ip} ifOutNUcastPkts | sed -e 's/^IF-MIB::ifOutNUcastPkts.*[0-9] = Counter32: //g' | sed -e 's/^IF-MIB::ifOutDiscards.*[0-9] = Counter32: //g')
sGetIn=$(snmpget -v 2c -c public ${ip} snmpInGetRequests.0 | sed -e 's/^SNMPv2-MIB::snmpInGetRequests.0 = Counter32: //g')
sGetOut=$(snmpget -v 2c -c public ${ip} snmpOutGetRequests.0 | sed -e 's/^SNMPv2-MIB::snmpOutGetRequests.0 = Counter32: //g')
sSetIn=$(snmpget -v 2c -c public ${ip} snmpInSetRequests.0 | sed -e 's/^SNMPv2-MIB::snmpInSetRequests.0 = Counter32: //g')
sSetOut=$(snmpget -v 2c -c public ${ip} snmpOutSetRequests.0 | sed -e 's/^SNMPv2-MIB::snmpOutSetRequests.0 = Counter32: //g')
sTrapIn=$(snmpget -v 2c -c public ${ip} snmpInTraps.0 | sed -e 's/^SNMPv2-MIB::snmpInTraps.0 = Counter32: //g')
sTrapOut=$(snmpget -v 2c -c public ${ip} snmpOutTraps.0 | sed -e 's/^SNMPv2-MIB::snmpOutTraps.0 = Counter32: //g')
rEntryCount=$(snmpbulkget -v 2c -Cr100 -c public ${ip} ipRouteIfIndex | grep RFC1213-MIB::ipRouteIfIndex | wc -l)
routeDest=$(snmpbulkget -v 2c -Cr100 -c public ${ip} ipRouteDest | grep RFC1213-MIB::ipRouteDest | sed -e 's/^RFC1213-MIB::ipRouteDest.*IpAddress: //g')
routeMask=$(snmpbulkget -v 2c -Cr100 -c public ${ip} ipRouteMask | grep RFC1213-MIB::ipRouteMask | sed -e 's/^RFC1213-MIB::ipRouteMask.*IpAddress: //g')
routeNHop=$(snmpbulkget -v 2c -Cr100 -c public ${ip} ipRouteNextHop | grep RFC1213-MIB::ipRouteNextHop | sed -e 's/^RFC1213-MIB::ipRouteNextHop.*IpAddress: //g')
routeProto=$(snmpbulkget -v 2c -Cr100 -c public ${ip} ipRouteProto | grep RFC1213-MIB::ipRouteProto | sed -e 's/^RFC1213-MIB::ipRouteProto.*INTEGER: //g' | cut -d "(" -f 1)
routeIf=$(snmpbulkget -v 2c -Cr100 -c public ${ip} ipRouteIfIndex | grep RFC1213-MIB::ipRouteIfIndex | sed -e 's/^RFC1213-MIB::ipRouteIfIndex.*INTEGER: //g')

pname=()
ptype=()
pmac=()
poper=()
ipt=()
indext=()
ifip=()
pinUpac=()
pinNUpac=()
pintotpac=()
poutUpac=()
poutNUpac=()
pouttotpac=()
rDest=()
rMask=()
rHop=()
rProto=()
rIf=()
devIn=0
devOut=0

for ((i=0; i<25; i++))
do
ifip[$i]="-"
done

index_t=$(snmpbulkget -v 2c -Cr50 -c public ${ip} IpAdEntAddr  | grep IP-MIB::ipAdEntIfIndex.*.INTEGER: | sort -n -t: -k4 | sed 's/^IP-MIB::ipAdEntIfIndex.* = INTEGER: //g')
ip_t=$(snmpbulkget -v 2c -Cr50 -c public ${ip} IpAdEntAddr  | grep IP-MIB::ipAdEntIfIndex.*.INTEGER: | sort -n -t: -k4 | cut -d "=" -f 1 | sed 's/^IP-MIB::ipAdEntIfIndex.//g')

IFS=' ' read -r -a indext <<< $index_t
IFS=' ' read -r -a ipt <<< $ip_t

for ((i=0; i<${#indext[@]}; i++))
do
c=${indext[$i]}
ifip[$c]=${ipt[$i]}
done

IFS=' ' read -r -a pname <<< $ifname
IFS=' ' read -r -a ptype <<< $iftype
IFS=' ' read -r -a pmac <<< $ifmac
IFS=' ' read -r -a poper <<< $ifoper

IFS=' ' read -r -a pinUpac <<< $ifinUpac
IFS=' ' read -r -a pinNUpac <<< $ifinNUpac
IFS=' ' read -r -a poutUpac <<< $ifoutUpac
IFS=' ' read -r -a poutNUpac <<< $ifoutNUpac

IFS=' ' read -r -a rDest <<< $routeDest
IFS=' ' read -r -a rMask <<< $routeMask
IFS=' ' read -r -a rHop <<< $routeNHop
IFS=' ' read -r -a rProto <<< $routeProto
IFS=' ' read -r -a rIf <<< $routeIf

echo -e "\nInterface Table for $hostname:\n============================"
printf " _____________________________________________________________________________________________________________________________________________________\n"
printf "|%-20s | %-30s | %-30s | %-10s| %-10s | %-10s | %-20s |\n" "Interface Name" "Type" "MAC Address" "Oper Status" "InPackets" "OutPackets" "IP Address"
printf "|%-20s | %-30s | %-30s | %-10s | %-10s | %-10s | %-20s |\n" "____________________" "______________________________" "______________________________" "__________" "__________" "__________" "____________________"


for ((i=1; i<= $ifnumber; i++))
do
if [ "${pname[$i - 1]}" == "Null0" ]
then 
    continue
else
    pintotpac[$i-1]=$((${pinUpac[$i - 1]} + ${pinNUpac[$i - 1]}))
    pouttotpac[$i-1]=`expr ${poutUpac[$i - 1]} + ${poutNUpac[$i - 1]}`
    ifi=${ifip[$i-1]}
    name=${pname[$i - 1]}
    type=${ptype[$i - 1]}
    mac=${pmac[$i - 1]}
    oper=${poper[$i - 1]}
    pacIn=${pintotpac[$i-1]}
    pacOut=${poutUpac[$i - 1]}
    devIn=$((${devIn} + ${pacIn}))
    devOut=$((${devOut} + ${pacOut}))
    printf "|%-20s | %-30s | %-30s | %-10s | %-10s | %-10s | %-20s |\n" "$name" "$type" "$mac" "$oper" "$pacIn" "$pacOut" "$ifi"
fi
done
echo -e "|_____________________________________________________________________________________________________________________________________________________|\n"
echo "Total Number of packets entering ${hostname}: ${devIn}"
echo "Total Number of packets leaving ${hostname}: ${devOut}"
printf "\n"

echo -e "\nRoute Table for $hostname:\n============================"
printf " _______________________________________________________________________________________________________\n"

printf "|%-20s | %-20s | %-20s | %-10s | %-20s |\n" "Destination IP" "Mask" "Next Hop" "Protocol" "Interface"
printf "|%-20s | %-20s | %-20s | %-10s | %-20s |\n" "____________________" "____________________" "____________________" "__________" "____________________"

for ((i=1; i<= $rEntryCount; i++))
do
    dest=${rDest[$i - 1]}
    mask=${rMask[$i - 1]}
    hop=${rHop[$i - 1]}
    prot=${rProto[$i - 1]}
    ind=${rIf[$i-1]}

    if [ $ind == 0 ] || [ -z $ind ]
    then 
        rname="<<Static Route>>"
    else
        rname=$(snmpget -v 2c -c public ${ip} ifDescr.$ind | sed -e 's/^IF-MIB::ifDescr.*[0-9] = STRING: //g')
    fi

    printf "|%-20s | %-20s | %-20s | %-10s | %-20s |\n" "$dest" "$mask" "$hop" "$prot" "$rname"
done

printf "|_______________________________________________________________________________________________________|\n"

echo -e "\nSNMP Table for $hostname:\n========================"
printf " _____________________________________________________________________________________________________________________________________________________________________\n"
printf "|%-25s | %-25s | %-25s | %-25s | %-25s | %-25s|\n" "SNMP Get Requests: In" "SNMP Get Requests: Out" "SNMP Set Requests: In" "SNMP Set Requests: Out" "SNMP Traps: In" "SNMP Traps: In"
printf "|%-25s | %-25s | %-25s | %-25s | %-25s | %-25s|\n" "_________________________" "_________________________" "_________________________" "_________________________" "_________________________" "_________________________"
printf "|%-25s | %-25s | %-25s | %-25s | %-25s | %-25s|\n" "$sGetIn" "$sGetOut" "$sSetIn" "$sSetOut" "$sTrapIn" "$sTrapOut"
echo -e "|_____________________________________________________________________________________________________________________________________________________________________|\n"

echo -e "#########################################################################################################################################################################"
done