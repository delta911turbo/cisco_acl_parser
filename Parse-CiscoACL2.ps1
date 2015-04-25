<#
.SYNOPSIS 
Cisco ACL Parser
v2.15b

.DESCRIPTION
	The script will take in a raw ACL file as input and generate a formated XML output file.

	The script will require an input file and produce an error if one is not provided.
	
	The script will generate an output file name based on the input file name if an output
	file is not provided.
	
	If found that the output file already exist, you will be prompted to confirm or deny
	overwriting the file.
	
	With the rejectedOutput switch you have the ability to enable output of all lines of the 
	left over data from the raw ACL file. This is used to confirm all data was successfully 
	parsed from the ACL. The switch is enabled with either a "yes" or "y"
    
.PARAMETER inputFile
     Path and file of the raw ACL fle

.PARAMETER outputFile
	Path and file of the XML output file
	
.PARAMETER rejectedOutput <string>
	Switch used to enable the rejected line output file. Used to output all lines found in
	the raw input file that do not contain information that used in output file.

.EXAMPLE
	./Parse-CiscoACL -inputFile FIREWALLACL01 -outputFile FirewallACL.XML

	./Parse-CiscoACL FIREWALLACL01 FirewallACL.XML

	./Parse-CiscoACL FIREWALLACL01 FirewallACL.XML -rejectedOutput yes
	
	./Parse-CiscoACL FIREWALLACL01 FirewallACL.XML yes
	
.NOTES
	Due to the 7 different standards used for output within the raw ACL file, checks for each type of
	line was required to process the entire ACL list.
	
	http://www.cisco.com/c/en/us/support/docs/ip/access-lists/26448-ACLsamples.html

.LINK
	https://github.com/delta911turbo/cisco_acl_parser
#>

param (

	[Parameter(Position=0,mandatory=$false)]
		[string] $inputFile,
    [Parameter(Position=1,mandatory=$false)]
		[string] $outputFile,
	[Parameter(Position=3,mandatory=$false)]
		[string] $rejectedOutput
 )

$fileName = "TESTCISCOFW"
$rej
## Gather contents of the input file and set to the inputFileContent variable ##
$inputFileContent = get-content $fileName
$ipAddresses = $null

## Set variable for starting progress percent ##
$i = 1

foreach ($line in $inputFileContent) {

	if ($line -match "access-list" -and $line -match "permit" -or $line -match "deny" -and $line -notmatch "object-group" -and $line -notmatch "remark") {

		## Matches hash based on finding 0x and 8 more characters/numbers ##
		$hash = ( $line | Select-String '0x[a-z0-9]{8}' ) | % { $_.Matches } | % { $_.Value }
		
		## Creates firewall name based on the file name with the extension removed. Formates to all upper case ##
		$firewallName = (((get-childitem $fileName).name) -Replace "\.[^.]+$","").toupper()
		
		## Splits line in 2 at first space and selected first word ##
		$interface = ( ($line -split " ")[1] | Select-String '\b([\w_0-9]{3,15})\b' ) | % { $_.Matches } | % { $_.Value }
		
		## Standard or Extended ACL list ##
		$standardExtended = ( $line | Select-String -pattern '\b(extended)\b','\b(standard)\b' ) | % { $_.Matches } | % { $_.Value }
		
		## ACL permit or deny rule ##
		$permitDeny =  ( $line | Select-String -pattern '\b(permit)\b','\b(deny)\b' -allmatches ) | % { $_.Matches } | % { $_.Value }
		
		## Checks the protocol and 
		$protocol =  ( $line | Select-String -pattern "\b(tcp)\b","\b(udp)\b","\b(ip)\b","\b(icmp)\b" -allmatches ) | % { $_.Matches } | % { $_.Value }

		
		## Search for source and destination IP Addresses based on each format of acceptable ACL list ##
		
	## ip sub ip sub ##	
		$ipAddresses = (( $line | Select-String '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' ) | % { $_.Matches } | % { $_.Value })
	
		if ($ipAddresses -eq $null ) {
	## ip sub host ip ##
			$ipAddresses = (( $line | Select-String '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(host)\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' ) | % { $_.Matches } | % { $_.Value })
		}
		if ($ipAddresses -eq $null) {
	## host ip host ip ##
			$ipAddresses = (( $line | Select-String '\b(host)\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(host)\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' ) | % { $_.Matches } | % { $_.Value })
		}
		if ($ipAddresses -eq $null) {
	## host ip ip sub ##	
			$ipAddresses = (( $line | Select-String '\b(host)\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' ) | % { $_.Matches } | % { $_.Value })
		}		 
		if ($ipAddresses -eq $null) {
	## any ip sub ##	
			$ipAddresses = (( $line | Select-String '\b(any).*\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' ) | % { $_.Matches } | % { $_.Value })
		} 
		if ($ipAddresses -eq $null) {
	## any host ip ##	
			$ipAddresses = (( $line | Select-String '\b(any).*\s(host)\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' ) | % { $_.Matches } | % { $_.Value })
		} 
		if ($ipAddresses -eq $null) {
	## ip sub any ##	
			$ipAddresses = (( $line | Select-String '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(any).*\b' ) | % { $_.Matches } | % { $_.Value })
		}
		if ($ipAddresses -eq $null) {
	## host ip any ##	
			$ipAddresses = (( $line | Select-String '\b(host)\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(any).*\b' ) | % { $_.Matches } | % { $_.Value })
		}
		if ($ipAddresses -eq $null) {
	## any any ##	
			$ipAddresses = (( $line | Select-String '\b(any).*\s(any).*\b' ) | % { $_.Matches } | % { $_.Value })									
		}
		
		## Subset of checks for standard format ACL ##
		if ($ipAddresses -eq $null -and $standardExtended -eq "standard") {
	## ip sub ##	
			$ipAddresses = (( $line | Select-String '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' ) | % { $_.Matches } | % ( $_.Value ))
		}
		if ($ipAddresses -eq $null -and $standardExtended -eq "standard") {
	## host ip ##	
			$ipAddresses = (( $line | Select-String '\b(host)\s(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' ) | % { $_.Matches } | % ( $_.Value ))
		}
		if ($ipAddresses -eq $null -and $standardExtended -eq "standard") {
	## any ##	
			$ipAddresses = (( $line | Select-String '\b(any).*\b' ) | % { $_.Matches } | % ( $_.Value ))
		}
		if ($ipAddresses -eq $null) {
		## Outputs all lines not found as acceptable ACL data ##
			$line | out-file rejected2.txt -append
		}
		
		## Based on value with a split ipAdresses array settings IP and subnet mask ##
		if (($ipAddresses -split " ")[0] -match "any") {
			$ipSource = "0.0.0.0"
			$subMaskSource = "0.0.0.0"
			
			if (($ipAddresses -split " ")[1] -match "any") { 
				$ipDestination = "0.0.0.0"
				$subMaskDestination = "0.0.0.0"
			} elseif (($ipAddresses -split " ")[1] -match "host") { 
				$ipDestination = ($ipAddresses -split " ")[2]
				$subMaskDestination = "255.255.255.255"
			} else {
				$ipDestination = ($ipAddresses -split " ")[1]
				$subMaskDestination = ($ipAddresses -split " ")[2]
			}
		} elseif (($ipAddresses -split " ")[0] -match "host") {
			$ipSource = ($ipAddresses -split " ")[1]
			$ipDestination = "255.255.255.255"
			
			if (($ipAddresses -split " ")[2] -match "any") { 
				$ipDestination = "0.0.0.0"
				$subMaskDestination = "0.0.0.0"
			} elseif (($ipAddresses -split " ")[2] -match "host") { 
				$ipDestination = ($ipAddresses -split " ")[3]
				$subMaskDestination = "255.255.255.255"
			} else {
				$ipDestination = ($ipAddresses -split " ")[2]
				$subMaskDestination = ($ipAddresses -split " ")[3]
			}
		} else {
			$ipSource = ($ipAddresses -split " ")[0]
			$subMaskDestination = ($ipAddresses -split " ")[1]
			
			if (($ipAddresses -split " ")[2] -match "any") { 
				$ipDestination = "0.0.0.0"
				$subMaskDestination = "0.0.0.0"
			} elseif (($ipAddresses -split " ")[2] -match "host") { 
				$ipDestination = ($ipAddresses -split " ")[3]
				$subMaskDestination = "255.255.255.255"
			} else {
				$ipDestination = ($ipAddresses -split " ")[2]
				$subMaskDestination = ($ipAddresses -split " ")[3]
			}
		}

		
		## Gathers various patterns used to list the port information ##
		$ipRange = ( $line | Select-String -pattern '\b(range)\b\s\d+\s\d+\b','\b(eq)\b\s\d+\b',"icmb",'\b(eq)\b\s.*\b' -allmatches ) | % { $_.Matches } | % { $_.Value }
		
		if ($ipRange -like "eq*") {
		## Splits the port and the service from the equal type
			$ipRange1 = $ipRange2 = ($ipRange -split " ")[1]
			$ipRange = ($ipRange -split " ")[0]
		}
		if ($ipRange -like "range*") {
		## Splits the range from the starting port and the ending port ##
			$ipRange1 = ($ipRange -split " ")[1]
			$ipRange2 = ($ipRange -split " ")[2]
			$ipRange = ($ipRange -split " ")[0]
		}
		if ($protocol -eq "icmp") {
		## Sets port variables for icmp to blank ##
			$ipRangeEqual = "icmp"
			$ipRange1 = ""
			$ipRange2 = ""
		}
		if ($protocol -eq "ip") {
		## IP as a protocol indicates the entire port range ##
			$ipRange1 = "1"
			$ipRange2 = "65535"
		}
	
	
	write-host "======================="
	$ipAddresses
	$ipSource
	$subMaskSource
	$ipDestination
	$subMaskDestination
	$protocol
	$permitDeny
	$firewallName 
	$interface
	$hash
	$standardExtended
	$ipRange
	$ipRange1
	$ipRange2
	
	$ipAddresses = $null
	$protocol = $null
	$permitDeny = $null
	$firewallName = $null
	$interface = $null
	$hash = $null
	$line = $null
	$standardExtended = $null
	$ipRange = $null
	$ipRange1 = $null
	$ipRange2 = $null
 
 #$b = ($a | Select-String  '(text-underline:none[^/"]*)' | %{$_.matches[0].value}).replace("text-underline:none'>","").replace(" <","").replace("<","").replace("   "," ")
		
#		$c = ($a | Select-String  'google.com/file') -replace '<a   href="',"" -replace '"   itemprop=url>',""
	}
}

