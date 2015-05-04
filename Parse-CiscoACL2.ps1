<#
.SYNOPSIS 
Cisco ACL Parser
v2.27c

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
	This is the second phase of the script that was rewritten to be more robust with changing
	ACL standards. As the acceptable ACL format that the various Cisco iOSs changes, the script 
	will need to be updated to make sure that all variants are detected.
	
	http://www.cisco.com/c/en/us/support/docs/ip/access-lists/26448-ACLsamples.html
	http://www.cisco.com/c/en/us/td/docs/security/asa/asa82/configuration/guide/config/acl_extended.html
	http://www.cisco.com/c/en/us/td/docs/security/asa/asa-command-reference/S/cmdref3/s2.html
	http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/acl_extended.html

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
 
## Check for input file provided via input argument ##
if (!($inputFile)) {

	write-host "No inputFile provided..." -foregroundcolor red -backgroundcolor black
	
	exit
	
} elseif (!(test-path $inputFile)) {

	write-host "Unable to location input file..." -foregroundcolor red -backgroundcolor black
		
	exit

} else {
	
	write-host "Valid file provided for inputFile..." -foregroundcolor white -backgroundcolor black
	
	$inputFileName = (((get-childitem $inputFile).name) -Replace "\.[^.]+$","").toupper()
	
	
	
}

## Check if output file provided and already exist ##
if (!($outputFile)) {

	write-host "No outputFile provided..." -foregroundcolor red -backgroundcolor black
	
	$outputFile = $inputFileName + ".xml"
	
	write-host "Generating outputFile based on inputFile name: " -foregroundcolor white -backgroundcolor black -nonewline; write-host $outputFile -foregroundcolor red -backgroundcolor black
	
} elseif (test-path $outputFile) {

	write-host "Output file already exist: " -foregroundcolor white -backgroundcolor black -nonewline; write-host $outputFile -foregroundcolor red -backgroundcolor black
	write-host "Overwrite output file: " -foregroundcolor white -backgroundcolor black
	
	$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
	$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
		
	$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
	if ($decision -eq 0) {
		Write-Host "Overwriting outputFile: " -foregroundcolor white -backgroundcolor black -nonewline; write-host $outputFile -foregroundcolor red -backgroundcolor black
	} else {
		Write-Host "Exiting Cisco Firewall ACL Parsing Script" -foregroundcolor red -backgroundcolor black
		exit
	}

} else {
	
	write-host "Valid file provided for outputFile..." -foregroundcolor white -backgroundcolor black
	
}

if ($outputFile -notmatch ".xml") {

	$outputFile = "$outputFile"+".xml"
	
}

write-host "Starting the parsing process..." -foregroundcolor white -backgroundcolor black

write-host "Parsing input file: " -foregroundcolor white -backgroundcolor black -nonewline; write-host $inputFile -foregroundcolor red -backgroundcolor black


## Set and clear input ACL file used for debugging output ##
$tempfile = "tempfile.txt"
$null > $tempfile

## Clear the output file ##
$null > $outputFile

## Set rejected lines file and clear it out ##
$rejectedOutFile = $inputFileName + " - rejected.txt"
$null > $rejectedOutFile
if ($rejectedOutput -eq "yes" -or $rejectedOutput -eq "y")  {
		
	write-host "Generating rejected line output file based on inputFile name: " -foregroundcolor white -backgroundcolor black -nonewline; write-host $rejectedOutFile -foregroundcolor red -backgroundcolor black 

}

## Gather contents of the input file and set to the inputFileContent variable ##
$inputFileContent = get-content $inputFile
$ipAddresses = $null

## Firewall Name ##
$firewallName = $inputFileName

### Header and footer of XML file ###

$XMLheader = @"
<ACLParse>
"@

$XMLfooter = @"
</ACLParse>
"@

## Output XML header to file ##
$XMLheader > $outputFile 

## Set variable for starting progress percent ##
$i = 1

## Regular Expression variables ##
$REGEX_IPAddress = '(?:[0-9]{1,3}\.){3}[0-9]{1,3}' ## Any form of IP Address ##
$REGEX_portvalid = "([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])" ## Validates ports between 1 and 65535 ##


foreach ($line in $inputFileContent) {

	write-progress -activity "Parsing ACL File" -status 'Progress->' -percentcomplete ($i/$inputFileContent.count*10)

	$line = (($line.replace("<--- More --->","")).trim()).replace("  ","")
	
	if ($line -match "permit" -or $line -match "deny" -and $line -notmatch "object-group" -and $line -notmatch "remark" -and $line -notmatch "cache") {

		## Matches hash based on finding 0x and 8 more characters/numbers ##
		$hash = ( $line | Select-String '0x[a-z0-9]{8}' ) | % { $_.Matches } | % { $_.Value }
		
		## Splits line in 2 at first space and selected first word ##
		$interface = ( ($line -split " ")[1] )
		
		## Standard or Extended ACL list ##
		$standardExtended = ( $line | Select-String -pattern '\b(extended)\b','\b(standard)\b' ) | % { $_.Matches } | % { $_.Value }
		
		## ACL permit or deny rule ##
		$permitDeny =  ( $line | Select-String -pattern '\b(permit)\b','\b(deny)\b' -allmatches ) | % { $_.Matches } | % { $_.Value }
		
		## Checks the protocol and 
		$protocol =  ( $line | Select-String -pattern "\b(tcp)\b","\b(udp)\b","\b(ip)\b","\b(icmp)\b" -allmatches ) | % { $_.Matches } | % { $_.Value }

		
		## Search for source and destination IP Addresses based on each format of acceptable ACL list ##
		## Sets the $ipAddresses variable to a string that includes all IP address formats used ##
		
	## ip sub ip sub ##	
		$ipAddresses = (( $line | Select-String "\b$REGEX_IPAddress\s$REGEX_IPAddress\s$REGEX_IPAddress\s$REGEX_IPAddress\b" ) | % { $_.Matches } | % { $_.Value })
		if ($ipAddresses -eq $null ) {
	## ip sub host ip ##
			$ipAddresses = (( $line | Select-String "\b$REGEX_IPAddress\s$REGEX_IPAddress\s(host)\s$REGEX_IPAddress\b" ) | % { $_.Matches } | % { $_.Value })
		}
		if ($ipAddresses -eq $null) {
	## host ip host ip ##
			$ipAddresses = (( $line | Select-String "\b(host)\s$REGEX_IPAddress\s(host)\s$REGEX_IPAddress\b" ) | % { $_.Matches } | % { $_.Value })
		}
		if ($ipAddresses -eq $null) {
	## host ip ip sub ##	
			$ipAddresses = (( $line | Select-String "\b(host)\s$REGEX_IPAddress\s$REGEX_IPAddress\s$REGEX_IPAddress\b" ) | % { $_.Matches } | % { $_.Value })
		}		 
		if ($ipAddresses -eq $null) {
	## any ip sub ##	
			$ipAddresses = (( $line | Select-String -pattern "\b(any)\d\s$REGEX_IPAddress\s$REGEX_IPAddress\b","\b(any)\s$REGEX_IPAddress\s$REGEX_IPAddress\b" ) | % { $_.Matches } | % { $_.Value })
		} 
		if ($ipAddresses -eq $null) {
	## any host ip ##	
			$ipAddresses = (( $line | Select-String -pattern "\b(any)\d\s(host)\s$REGEX_IPAddress\b","\b(any)\s(host)\s$REGEX_IPAddress\b" ) | % { $_.Matches } | % { $_.Value })
		} 
		if ($ipAddresses -eq $null) {
	## ip sub any ##	
			$ipAddresses = (( $line | Select-String -pattern "\b$REGEX_IPAddress\s$REGEX_IPAddress\s(any)\d\b","\b$REGEX_IPAddress\s$REGEX_IPAddress\s(any)\b" ) | % { $_.Matches } | % { $_.Value })
		}
		if ($ipAddresses -eq $null) {
	## host ip any ##	
			$ipAddresses = (( $line | Select-String -pattern "\b(host)\s$REGEX_IPAddress\s(any)\d\b","\b(host)\s$REGEX_IPAddress\s(any)\d\b" ) | % { $_.Matches } | % { $_.Value })
		}
		if ($ipAddresses -eq $null) {
	## any any ##	
			$ipAddresses = (( $line | Select-String -pattern "\b(any)\d\s(any)\d\b","\b(any)\s(any)\b" ) | % { $_.Matches } | % { $_.Value })									
		}
		
		## Subset of checks for standard format ACL ##
		if ($ipAddresses -eq $null -and $standardExtended -eq "standard") {
	## ip sub ##	
			$ipAddresses = (( $line | Select-String '\b$REGEX_IPAddress\s$REGEX_IPAddress\b' ) | % { $_.Matches } | % ( $_.Value ))
		}
		if ($ipAddresses -eq $null -and $standardExtended -eq "standard") {
	## host ip ##	
			$ipAddresses = (( $line | Select-String '\b(host)\s$REGEX_IPAddress\b' ) | % { $_.Matches } | % ( $_.Value ))
		}
		if ($ipAddresses -eq $null -and $standardExtended -eq "standard") {
	## any ##	
			$ipAddresses = (( $line | Select-String -pattern '\s\b(any)\b\s','\b(any)\d\b' ) | % { $_.Matches } | % ( $_.Value ))
		}
		if ($ipAddresses -eq $null) {
		## Outputs all lines not found as acceptable ACL data ##
			if ($rejectedOutput -eq "yes" -or $rejectedOutput -eq "y")  {
				$line | out-file $rejectedOutFile -append
			}
		}
		
		## Based on value with a split ipAdresses array settings IP and subnet mask ##
		if (($ipAddresses -split " ")[0] -match "any") {
			$sourceIP = "0.0.0.0"
			$sourceSubnetMask = "0.0.0.0"
			
			if (($ipAddresses -split " ")[1] -match "any") { 
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			} elseif (($ipAddresses -split " ")[1] -match "host") { 
				$destinationIP = ($ipAddresses -split " ")[2]
				$destinationSubnetMask = "255.255.255.255"
			} else {
				$destinationIP = ($ipAddresses -split " ")[1]
				$destinationSubnetMask = ($ipAddresses -split " ")[2]
			}
		} elseif (($ipAddresses -split " ")[0] -match "host") {
			$sourceIP = ($ipAddresses -split " ")[1]
			$sourceSubnetMask = "255.255.255.255"
			
			if (($ipAddresses -split " ")[2] -match "any") { 
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			} elseif (($ipAddresses -split " ")[2] -match "host") { 
				$destinationIP = ($ipAddresses -split " ")[3]
				$destinationSubnetMask = "255.255.255.255"
			} else {
				$destinationIP = ($ipAddresses -split " ")[2]
				$destinationSubnetMask = ($ipAddresses -split " ")[3]
			}
		} else {
			$sourceIP = ($ipAddresses -split " ")[0]
			$sourceSubnetMask = ($ipAddresses -split " ")[1]
			
			if (($ipAddresses -split " ")[2] -match "any") { 
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			} elseif (($ipAddresses -split " ")[2] -match "host") { 
				$destinationIP = ($ipAddresses -split " ")[3]
				$destinationSubnetMask = "255.255.255.255"
			} else {
				$destinationIP = ($ipAddresses -split " ")[2]
				$destinationSubnetMask = ($ipAddresses -split " ")[3]
			}
		}


		## Gathers various patterns used to list the port information ##
		$ipRange = ( $line | Select-String -pattern "\b(gt)\b\s$REGEX_portvalid\b","\b(range)\b\s$REGEX_portvalid\s$REGEX_portvalid\b","icmb",'\b(eq)\b\s.*\b',"\b(lt)\b\s$REGEX_portvalid\b","\b(eq)\b\s$REGEX_portvalid\b" -allmatches ) | % { $_.Matches } | % { $_.Value }
		
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
		if ($ipRange -like "gt*") {
			
			
			$ipRange1 = ($ipRange -split " ")[1]
			$ipRange2 = "65535"
			$ipRange = ($ipRange -split " ")[0]
		} 
		if ($ipRange -like "lt*") {
			
			
			$ipRange2 = ($ipRange -split " ")[1]
			$ipRange1 = "1"
			$ipRange = ($ipRange -split " ")[0]
		}
		if ($protocol -eq "icmp") {
		## Sets port variables for icmp to blank ##
			$ipRange = "icmp"
			$ipRange1 = ""
			$ipRange2 = ""
		}
		if ($protocol -eq "ip") {
		## IP as a protocol indicates the entire port range ##
			$ipRange = "all"
			$ipRange1 = "1"
			$ipRange2 = "65535"
		}
		if ($protocol -eq "tcp" -and $ipRange -eq $null) {
		
			$ipRange = "all"
			$ipRange1 = "1"
			$ipRange2 = "65535"
		}
		
		$hitcount =  ($line | select-string '(\(hitcnt=+\b([0-9]{1,10}|100000000000)\b)'    | % { $_.Matches } | % { $_.Value }).replace('(hitcnt=',"")
	
	
	
## On-screen output for debugging purposes ##
$null = @'	

write-host "======================="
	$ipAddresses
	$sourceIP
	$sourceSubnetMask
	$destinationIP
	$destinationSubnetMask
	$protocol
	$permitDeny
	$firewallName 
	$interface
	$hash
	$standardExtended
	$ipRange
	$ipRange1
	$ipRange2
	$hitcount
'@

	
$ACLTable = @"
	<ACL_List Hash="$hash">
		<FirewallName Interface="$interface" ACL_Type="$standardExtended" Protocol="$protocol" Permit_Deny="$permitDeny" SourceIP="$sourceIP" SourceSubnetMask="$sourceSubnetMask" DestinationIP="$destinationIP" DestinationSubnetMask="$destinationSubnetMask" IPRangeEqual="$ipRange" IPRange1="$ipRange1" IPRange2="$ipRange2">$firewallName</FirewallName>
	</ACL_List>
"@
	
	$ACLTable | out-file $outputFile -append
	
	$ipAddresses = $null
	$sourceIP = $null
	$sourceSubnetMask = $null
	$destinationIP = $null
	$destinationSubnetMask = $null
	$protocol = $null
	$permitDeny = $null
	$interface = $null
	$hash = $null
	$line = $null
	$standardExtended = $null
	$ipRange = $null
	$ipRange1 = $null
	$ipRange2 = $null
	$hitcount = $null
 
 ## If line does not conform to any of the checks the line is added to the rejectedOutFile ##
 } else {
 
	if ($rejectedOutput -eq "yes" -or $rejectedOutput -eq "y")  {
	
		$line | out-file $rejectedOutFile -append
	
	}

 }
 
 
 
 $i++
}


$XMLfooter | out-file $outputFile -append
