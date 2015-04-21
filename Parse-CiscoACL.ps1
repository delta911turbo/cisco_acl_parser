<#
.SYNOPSIS 
Cisco ACL Raw Parser
v1.2.8

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
	
}

if (test-path $outputFile) {

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
write-host "Generating output file: " -foregroundcolor white -backgroundcolor black -nonewline; write-host $outputFile -foregroundcolor red -backgroundcolor black	
### File variables ##

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

### Header and footer of XML file ###

$XMLheader = @"
<FirewallParse>
"@

$XMLfooter = @"
</FirewallParse>
"@

## Output XML header to file ##
$XMLheader > $outputFile 


## Gather contents of the input file and set to the inputFileContent variable ##
$inputFileContent = get-content "$inputFile"

## Set variable for starting progress percent ##
$i = 1

foreach ($line in $inputFileContent) {

write-progress -activity "Parsing ACL File" -status 'Progress->' -percentcomplete ($i/$inputFileContent.count*100)

## Splits each line by the blank space between words into an array and removes any blank lines ##
	$lineSplit = $line.split(' ') | ? {$_}
	
### IP Range - 16 Elements  ###

	if ($line -match "access-list" -and $line -match "line" -and $line -match "range" -and $lineSplit.count -eq "16" -and $line -notmatch "Eracent" -and $line -notmatch "object-group" -and $line -notmatch "remark") {

## -- Debugging Code --	##	$line | out-file $tempfile -append
	
		$hashNumber = $lineSplit.count - 1
		$hash = $lineSplit[$hashNumber]
		$firewallName = $inputFileName
		$extended = $lineSplit[4]
		$interface = $lineSplit[1]
		$protocol = $lineSplit[6]
		
		if ($lineSplit[7] -eq "host") {
		
			$sourceIP = $lineSplit[8]
			$sourceSubnetMask = "255.255.255.255"
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		} elseif ($lineSplit[7] -match "any") {
		
			$sourceIP = "0.0.0.0"
			$sourceSubnetMask = "0.0.0.0"

			if ($lineSplit[8] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[8] -eq "host") {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[8]
				$destinationSubnetMask = $lineSplit[9]
				
			}
		
		}else {
		
			$sourceIP = $lineSplit[7]
			$sourceSubnetMask = $lineSplit[8]
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		}
		
		if ($protocol -eq "icmp") {
		
			$IPRangeEqual = "icmp"
			$IPRange1 = ""
			$IPRange2 = ""

		
		} else {
		
			$IPRangeEqual = $lineSplit[11]
			$IPRange1 = $lineSplit[12]
			$IPRange2 = $lineSplit[13]
			
		}
		
		$firewallTable = @"
	<Firewall_Access Hash="$hash">
		<FirewallName Interface="$interface" Extended="$extended" Protocol="$protocol" SourceIP="$sourceIP" SourceSubnetMask="$sourceSubnetMask" DestinationIP="$destinationIP" DestinationSubnetMask="$destinationSubnetMask" IPRangeEqual="$IPRangeEqual" IPRange1="$IPRange1" IPRange2="$IPRange2">$firewallName</FirewallName>
	</Firewall_Access>
"@

	$firewallTable | out-file $outputFile -append

	}
	
### IP No Range - 15 Elements ###

	elseif ($line -match "access-list" -and $line -match "line" -and $lineSplit.count -eq "15" -and $line -notmatch "Eracent" -and $line -notmatch "object-group" -and $line -notmatch "remark") {
	
## -- Debugging Code --	##	$line | out-file $tempfile -append
	
		$hashNumber = $lineSplit.count - 1
		$hash = $lineSplit[$hashNumber]
		$firewallName = $inputFileName
		$extended = $lineSplit[4]
		$interface = $lineSplit[1]
		$protocol = $lineSplit[6]
		
		if ($lineSplit[7] -eq "host") {
		
			$sourceIP = $lineSplit[8]
			$sourceSubnetMask = "255.255.255.255"
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		} elseif ($lineSplit[7] -match "any") {
		
			$sourceIP = "0.0.0.0"
			$sourceSubnetMask = "0.0.0.0"

			if ($lineSplit[8] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[8] -eq "host") {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[8]
				$destinationSubnetMask = $lineSplit[9]
				
			}
		
		}else {
		
			$sourceIP = $lineSplit[7]
			$sourceSubnetMask = $lineSplit[8]
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		}
		
		if ($protocol -eq "icmp") {
		
			$IPRangeEqual = "icmp"
			$IPRange1 = ""
			$IPRange2 = ""

		
		} else {
		
			$IPRangeEqual = $lineSplit[11]
			$IPRange1 = $lineSplit[12]
			$IPRange2 = $lineSplit[12]
		
		}
		
		$firewallTable = @"
	<Firewall_Access Hash="$hash">
		<FirewallName Interface="$interface" Extended="$extended" Protocol="$protocol" SourceIP="$sourceIP" SourceSubnetMask="$sourceSubnetMask" DestinationIP="$destinationIP" DestinationSubnetMask="$destinationSubnetMask" IPRangeEqual="$IPRangeEqual" IPRange1="$IPRange1" IPRange2="$IPRange2">$firewallName</FirewallName>
	</Firewall_Access>
"@

	$firewallTable | out-file $outputFile -append

	}
	
### IP No Range - 14 Elements ###

	elseif ($line -match "access-list" -and $line -match "line" -and $lineSplit.count -eq "14" -and $line -notmatch "Eracent" -and $line -notmatch "object-group" -and $line -notmatch "remark") {

## -- Debugging Code --	##	$line | out-file $tempfile -append
	
		$hashNumber = $lineSplit.count - 1
		$hash = $lineSplit[$hashNumber]
		$firewallName = $inputFileName
		$extended = $lineSplit[4]
		$interface = $lineSplit[1]
		$protocol = $lineSplit[6]
		
		if ($lineSplit[7] -eq "host") {
		
			$sourceIP = $lineSplit[8]
			$sourceSubnetMask = "255.255.255.255"
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		} elseif ($lineSplit[7] -match "any") {
		
			$sourceIP = "0.0.0.0"
			$sourceSubnetMask = "0.0.0.0"

			if ($lineSplit[8] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[8] -eq "host") {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[8]
				$destinationSubnetMask = $lineSplit[9]
				
			}
		
		}else {
		
			$sourceIP = $lineSplit[7]
			$sourceSubnetMask = $lineSplit[8]
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		}
		
		if ($protocol -eq "icmp") {
		
			$IPRangeEqual = "icmp"
			$IPRange1 = ""
			$IPRange2 = ""
	
		} else {
		
			$IPRangeEqual = $lineSplit[10]
			$IPRange1 = $lineSplit[11]
			$IPRange2 = $lineSplit[11]
		
		}
		
		$firewallTable = @"
	<Firewall_Access Hash="$hash">
		<FirewallName Interface="$interface" Extended="$extended" Protocol="$protocol" SourceIP="$sourceIP" SourceSubnetMask="$sourceSubnetMask" DestinationIP="$destinationIP" DestinationSubnetMask="$destinationSubnetMask" IPRangeEqual="$IPRangeEqual" IPRange1="$IPRange1" IPRange2="$IPRange2">$firewallName</FirewallName>
	</Firewall_Access>
"@

	$firewallTable | out-file $outputFile -append

	}
		
### IP No Range - 13 Elements ###

	elseif ($line -match "access-list" -and $line -match "line" -and $lineSplit.count -eq "13" -and $line -notmatch "Eracent" -and $line -notmatch "object-group" -and $line -notmatch "remark") {
		
## -- Debugging Code --	##	$line | out-file $tempfile -append
		
		$hashNumber = $lineSplit.count - 1
		$hash = $lineSplit[$hashNumber]
		$firewallName = $inputFileName
		$extended = $lineSplit[4]
		$interface = $lineSplit[1]
		$protocol = $lineSplit[6]
		
		if ($lineSplit[7] -eq "host") {
		
			$sourceIP = $lineSplit[8]
			$sourceSubnetMask = "255.255.255.255"
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		} elseif ($lineSplit[7] -match "any") {
		
			$sourceIP = "0.0.0.0"
			$sourceSubnetMask = "0.0.0.0"

			if ($lineSplit[8] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[8] -eq "host") {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[8]
				$destinationSubnetMask = $lineSplit[9]
				
			}
		
		}else {
		
			$sourceIP = $lineSplit[7]
			$sourceSubnetMask = $lineSplit[8]
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		}
		
		
		if ($protocol -eq "icmp") {
		
			$IPRangeEqual = "icmp"
			$IPRange1 = ""
			$IPRange2 = ""

		
		} else {
		
			$IPRangeEqual = "range"
			$IPRange1 = "1"
			$IPRange2 = "65535"
		
		}
		
		$firewallTable = @"
	<Firewall_Access Hash="$hash">
		<FirewallName Interface="$interface" Extended="$extended" Protocol="$protocol" SourceIP="$sourceIP" SourceSubnetMask="$sourceSubnetMask" DestinationIP="$destinationIP" DestinationSubnetMask="$destinationSubnetMask" IPRangeEqual="$IPRangeEqual" IPRange1="$IPRange1" IPRange2="$IPRange2">$firewallName</FirewallName>
	</Firewall_Access>
"@

	$firewallTable | out-file $outputFile -append

	}
		
### IP No Range - 12 Elements ###

	elseif ($line -match "access-list" -and $line -match "line" -and $lineSplit.count -eq "12" -and $line -notmatch "Eracent" -and $line -notmatch "object-group" -and $line -notmatch "remark") {
		
## -- Debugging Code --	##	$line | out-file $tempfile -append
		
		$hashNumber = $lineSplit.count - 1
		$hash = $lineSplit[$hashNumber]
		$firewallName = $inputFileName
		$extended = $lineSplit[4]
		$interface = $lineSplit[1]
		$protocol = $lineSplit[6]
		
		if ($lineSplit[7] -eq "host") {
		
			$sourceIP = $lineSplit[8]
			$sourceSubnetMask = "255.255.255.255"
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		} elseif ($lineSplit[7] -match "any") {
		
			$sourceIP = "0.0.0.0"
			$sourceSubnetMask = "0.0.0.0"

			if ($lineSplit[8] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[8] -eq "host") {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[8]
				$destinationSubnetMask = $lineSplit[9]
				
			}
		
		}else {
		
			$sourceIP = $lineSplit[7]
			$sourceSubnetMask = $lineSplit[8]
			
			if ($lineSplit[9] -match "any") {
			
				$destinationIP = "0.0.0.0"
				$destinationSubnetMask = "0.0.0.0"
			
			} elseif ($lineSplit[9] -eq "host") {
			
				$destinationIP = $lineSplit[10]
				$destinationSubnetMask = "255.255.255.255"
			
			} else {
			
				$destinationIP = $lineSplit[9]
				$destinationSubnetMask = $lineSplit[10]
				
			}
		
		}
		
		if ($protocol -eq "icmp") {
		
			$IPRangeEqual = "icmp"
			$IPRange1 = ""
			$IPRange2 = ""

		
		} else {
		
			$IPRangeEqual = "range"
			$IPRange1 = "1"
			$IPRange2 = "65535"
		
		}
		
		$firewallTable = @"
	<Firewall_Access Hash="$hash">
		<FirewallName Interface="$interface" Extended="$extended" Protocol="$protocol" SourceIP="$sourceIP" SourceSubnetMask="$sourceSubnetMask" DestinationIP="$destinationIP" DestinationSubnetMask="$destinationSubnetMask" IPRangeEqual="$IPRangeEqual" IPRange1="$IPRange1" IPRange2="$IPRange2">$firewallName</FirewallName>
	</Firewall_Access>
"@

	$firewallTable | out-file $outputFile -append

	}
		
## If line does not conform to any of the checks the line is added to the rejectedOutFile ##
	else {
	
		if ($rejectedOutput -eq "yes" -or $rejectedOutput -eq "y")  {
		
			$line | out-file $rejectedOutFile -append
		
		}
	
	}
	
	$i++
}

$XMLfooter | out-file $outputFile -append

