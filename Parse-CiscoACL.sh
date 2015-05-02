#!/bin/bash

REGEX_IPAddress='[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'

OutFile="output.xml"
InputFile="input.txt"

XMLheader="
<ACLParse>
"

XMLfooter="
</ACLParse>
"

## Output XML header to file ##
echo "$XMLheader" >> "$OutFile"

while read line; do
	if echo $line | grep 'access-list' | grep -E 'permit|deny' | grep -v 'object-group' | grep -v 'cache' -q; then
		hash=$(echo $line | grep -o '0x[a-z0-9]\{8\}')
		splitLine=($line)
		interface=${splitLine[1]}
		standardExtended=$(echo $line | grep -o -E '\sstandard\s|\sextended\s')
		permitDeny=$(echo $line | grep -o -E '\spermit\s|\sdeny\s')
		protocol=$(echo $line | grep -o -E '\stcp\s|\sudp\s|\sip\s|\sicmp\s')
		
			
		## ip sub ip sub ##
		ipAddresses=$(echo $line | grep -o "$REGEX_IPAddress\s$REGEX_IPAddress\s$REGEX_IPAddress\s$REGEX_IPAddress")
		## ip sub host ip ##
		if [ -z "$ipAddresses" ] 
			then
				ipAddresses=$(echo $line | grep -o "$REGEX_IPAddress\s$REGEX_IPAddress\shost\s$REGEX_IPAddress")
		fi
		## host ip host ip ##
		if [ -z "$ipAddresses" ]
			then
                        	ipAddresses=$(echo $line | grep -o "host\s$REGEX_IPAddress\shost\s$REGEX_IPAddress")
		fi
		## host ip ip sub ##
                if [ -z "$ipAddresses" ]
			then
                        	ipAddresses=$(echo $line | grep -o "host\s$REGEX_IPAddress\s$REGEX_IPAddress\s$REGEX_IPAddress")
		fi
		## any ip sub ##
                if [ -z "$ipAddresses" ]
                        then    
                                ipAddresses=$(echo $line | grep -o "any\s$REGEX_IPAddress\s$REGEX_IPAddress")
                fi  
		## any host ip ##
                if [ -z "$ipAddresses" ]
                        then    
                                ipAddresses=$(echo $line | grep -o "any\shost\s$REGEX_IPAddress")
                fi  
		## ip sub any ##
                if [ -z "$ipAddresses" ]
                        then    
                                ipAddresses=$(echo $line | grep -o "$REGEX_IPAddress\s$REGEX_IPAddress\sany")
                fi  
		## host ip any ##
                if [ -z "$ipAddresses" ]
                        then    
                            	ipAddresses=$(echo $line | grep -o "host\s$REGEX_IPAddress\sany")
                fi  
		## any any ##
                if [ -z "$ipAddresses" ]
                        then    
                                ipAddresses=$(echo $line | grep -o "any\sany")
                fi  	


		## Rejected lines not equal to any other ipAddress pattern ##
                if [ -z "$ipAddresses" ]
                        then    
	 			echo "$line"$'\r' >> "rejectedLines.txt"
                fi  

		ipAddressSplit=($ipAddresses)

		if [ ${ipAddressSplit[0]} = "any" ]
			then
				sourceIP="0.0.0.0"
				sourceSubnetMask="0.0.0.0"

				if [ ${ipAddressSplit[1]} = "any" ]
					then
						destinationIP="0.0.0.0"
						destinationSubnetMask="0.0.0.0"
				elif [ ${ipAddressSplit[1]} = "host" ]
					then
						destinationIP=${ipAddressSplit[2]}
						destinationSubnetMask="255.255.255.255"
				else
						destinationIP=${ipAddressSplit[1]}
						destinationSubnetMask=${ipAddressSplit[2]}
				fi

		elif [ ${ipAddressSplit[0]} = "host" ]
			then
				sourceIP=${ipAddressSplit[1]}
				sourceSubnetMask="255.255.255.255"
				
				if [ ${ipAddressSplit[2]} = "any" ]
                                        then
                                                destinationIP="0.0.0.0"
                                                destinationSubnetMask="0.0.0.0"
                                elif [ ${ipAddressSplit[2]} = "host" ]
                                        then
                                                destinationIP=${ipAddressSplit[3]}
                                                destinationSubnetMask="255.255.255.255"
                                else
                                                destinationIP=${ipAddressSplit[2]}
                                                destinationSubnetMask=${ipAddressSplit[3]}
                                fi  
		else
				sourceIP=${ipAddressSplit[0]}
                                sourceSubnetMask=${ipAddressSplit[1]}

                                if [ ${ipAddressSplit[2]} = "any" ]
                                        then
                                                destinationIP="0.0.0.0"
                                                destinationSubnetMask="0.0.0.0"
                                elif [ ${ipAddressSplit[2]} = "host" ]
                                        then
                                                destinationIP=${ipAddressSplit[3]}
                                                destinationSubnetMask="255.255.255.255"
                                else
                                                destinationIP=${ipAddressSplit[2]}
                                                destinationSubnetMask=${ipAddressSplit[3]}
                                fi
		fi

		ipRange=$(echo $line | grep -o "\sgt\s.*\|\seq\s.*\|\srange\s.*")
		
		if [ "${protocol//[[:blank:]]/}" = "icmp" ]
			then
				ipRangeType="icmp"
                                ipRange1=""
                                ipRange2=""

		elif [ -z "$ipRange" ]
			then
				ipRangeType="all"
                                ipRange1="1"
                                ipRange2="65535"

		else
				ipRangeSplit=($ipRange)
				if [ ${ipRangeSplit[0]} = "eq" ]
					then
						ipRangeType=${ipRangeSplit[0]}
						ipRange1=${ipRangeSplit[1]}
						ipRange2=${ipRangeSplit[1]}

				elif [ ${ipRangeSplit[0]} = "gt" ]
					then
						ipRangeType=${ipRangeSplit[0]}
                                		ipRange1=${ipRangeSplit[1]}
                                		ipRange2="65535"

				elif [ ${ipRangeSplit[0]} = "range" ]
					then
						ipRangeType=${ipRangeSplit[0]}
                                		ipRange1=${ipRangeSplit[1]}
                                		ipRange2=${ipRangeSplit[2]}
				fi		
		fi
		

 
	echo $hash
	echo $interface
	echo ${standardExtended//[[:blank:]]/}
	echo ${permitDeny//[[:blank:]]/}
	echo ${protocol//[[:blank:]]/}
	echo $sourceIP
	echo $sourceSubnetMask
	echo $destinationIP
	echo $destinationSubnetMask
	echo $ipRange
	echo $ipRangeType
	echo $ipRange1
	echo $ipRange2

ACLTable="	<ACL_List Hash='$hash'>
		<FirewallName Interface='$interface' ACL_Type='${standardExtended//[[:blank:]]/}' Protocol='${protocol//[[:blank:]]/}' Permit_Deny='${permitDeny//[[:blank:]]/}' SourceIP='$sourceIP' SourceSubnetMask='$sourceSubnetMask' DestinationIP='$destinationIP' DestinationSubnetMask='$destinationSubnetMask' IPRangeEqual='$ipRangeType' IPRange1='$ipRange1' IPRange2='$ipRange2'>$firewallName</FirewallName>
	</ACL_List>"

	echo "$ACLTable"$'\r' >> "$OutFile"

	unset hash
        unset interface
        #unset {standardExtended//[[:blank:]]/}
        #unset {permitDeny//[[:blank:]]/}
        #unset {protocol//[[:blank:]]/}
        unset sourceIP
        unset sourceSubnetMask
        unset destinationIP
        unset destinationSubnetMask
        unset ipRange

	fi
done <"$InputFile"

echo "$XMLfooter" >> "$OutFile"
