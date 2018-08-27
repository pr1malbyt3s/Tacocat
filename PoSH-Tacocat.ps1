<#
.SYNOPSIS  
    PoSH-Tacocat is a set of Windows Management Instrumentation interface (WMI) scripts that investigators and forensic analysts can use to retrieve information from a 
    compromised (or potentially compromised) Windows system. The scripts use WMI to pull this information from the operating system. Therefore, this script 
    will need to be executed with a user that has the necessary privileges.

    PoSH-Tacocat will retrieve the following data from an individual machine or a group of systems:       
            - Autorun entries
            - Disk info
            - Environment variables
            - Event logs (50 latest)
            - Installed Software (Warning: https://gregramsey.net/2012/02/20/Win32_product-is-evil/)
            - Logon sessions
            - List of drivers
            - List of mapped network drives
            - List of running processes/network connections
            - DLLs/hashes of running processes
            - Logged in user
            - Local groups
            - Local user accounts
            - Network configuration
            - Patches
            - Scheduled tasks with AT command
            - Shares
            - Services
            - System Information

.EXAMPLE
    .\posh_Tacocat.ps1

.NOTES  
    File Name      : PoSH-Tacocat.ps1
    Version        : v.2
    Author         : @WiredPulse
    Updated        : @Putztech
    Prerequisite   : PowerShell
    Created        : 10 Oct 16
    Modified       : 23 Aug 18
#>


# ==============================================================================
# Function Name 'ListComputers' - Takes entered domain and lists all computers
# ==============================================================================
Function ListComputers
{
    $DN = ""
    $Response = ""
    $DNSName = ""
    $DNSArray = ""
    $objSearcher = ""
    $colProplist = ""
    $objComputer = ""
    $objResults = ""
    $colResults = ""
    $Computer = ""
    $comp = ""
    New-Item -type file -force ".\Computer_List_$Script:curDate.txt" | Out-Null
    $Script:Compute = ".\Computer_List_$Script:curDate.txt"
    $strCategory = "(ObjectCategory=Computer)"
    
    Write-Host "Would you like to automatically pull from your domain or provide your own domain?"
    Write-Host "Auto pull uses the current domain you are on, if you need to Select-Object a different domain use manual."
    $response = Read-Host = "[1] Auto Pull, [2] Manual Select-Objection"
    
    If($Response -eq "1") {
        $DNSName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        If($DNSName -ne $Null) {
            $DNSArray = $DNSName.Split(".") 
            for ($x = 0; $x -lt $DNSArray.Length ; $x++) {  
                if ($x -eq ($DNSArray.Length - 1)){$Separator = ""}else{$Separator =","} 
                [string]$DN += "DC=" + $DNSArray[$x] + $Separator  } }
        $Script:Domain = $DN
        echo "Pulled computers from: "$Script:Domain 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$Script:Domain")
        $objSearcher.Filter = $strCategory
        $objSearcher.PageSize = 100000
        $objSearcher.SearchScope = "SubTree"
        $colProplist = "name"
        ForEach ($i in $colPropList) {
            $objSearcher.propertiesToLoad.Add($i) }
        $colResults = $objSearcher.FindAll()
        ForEach ($objResult in $colResults) {
            $objComputer = $objResult.Properties
            $comp = $objComputer.name
            echo $comp | Out-File $Script:Compute -Append }
        $Script:Computers = (Get-Content $Script:Compute) | Sort-Object
    }
	elseif($Response -eq "2")
    {
        Write-Host "Would you like to automatically pull from your domain or provide your own domain?"
        Write-Host "Auto pull uses the current domain you are on, if you need to Select-Object a different domain use manual."
        $Script:Domain = Read-Host "Enter your Domain here: OU=West,DC=Company,DC=com"
        If ($Script:Domain -eq $Null) {Write-Host "You did not provide a valid response."; . ListComputers}
        echo "Pulled computers from: "$Script:Domain 
        $objOU = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Script:Domain")
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objOU
        $objSearcher.Filter = $strCategory
        $objSearcher.PageSize = 100000
        $objSearcher.SearchScope = "SubTree"
        $colProplist = "name"
        ForEach ($i in $colPropList) { $objSearcher.propertiesToLoad.Add($i) }
        $colResults = $objSearcher.FindAll()
        ForEach ($objResult in $colResults) {
            $objComputer = $objResult.Properties
            $comp = $objComputer.name
            echo $comp | Out-File $Script:Compute -Append }
        $Script:Computers = (Get-Content $Script:Compute) | Sort-Object
    }
    else {
        Write-Host "You did not supply a correct response, Please Select-Object a response." -foregroundColor Red
        . ListComputers }
}

# ==============================================================================
# Function Name 'ListTextFile' - Enumerates Computer Names in a text file
# Create a text file and enter the names of each computer. One computer
# name per line. Supply the path to the text file when prompted.
# ==============================================================================
Function ListTextFile 
{
	$file_Dialog = ""
    $file_Name = ""
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $file_Dialog = New-Object system.windows.forms.openfiledialog
    $file_Dialog.InitialDirectory = "$env:USERPROFILE\Desktop"
    $file_Dialog.MultiSelect = $false
    $file_Dialog.showdialog()
    $file_Name = $file_Dialog.filename
    $Comps = Get-Content $file_Name
    If ($Comps -eq $Null) {
        Write-Host "Your file was empty. You must Select-Object a file with at least one computer in it." -Fore Red
        . ListTextFile }
    Else
    {
        $Script:Computers = @()
        ForEach ($Comp in $Comps)
        {
            If ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
            {
                $Temp = $Comp.Split("/")
                $IP = $Temp[0]
                $Mask = $Temp[1]
                . Get-Subnet-Range $IP $Mask
                $Script:Computers += $Script:IPList
            }
            Else
            {
                $Script:Computers += $Comp
            }
        }      
    }
}

Function Get-Subnet-Range {
    #.Synopsis
    # Lists all IPs in a subnet.
    #.Example
    # Get-Subnet-Range -IP 192.168.1.0 -Netmask /24
    #.Example
    # Get-Subnet-Range -IP 192.168.1.128 -Netmask 255.255.255.128        
    Param(
        [string]
        $IP,
        [string]
        $netmask
    )  
    Begin {
        $IPs = New-Object System.Collections.ArrayList

        Function Get-NetworkAddress {
            #.Synopsis
            # Get the network address of a given lan segment
            #.Example
            # Get-NetworkAddress -IP 192.168.1.36 -mask 255.255.255.0
            Param (
                [string]
                $IP,
               
                [string]
                $Mask,
               
                [switch]
                $Binary
            )
            Begin {
                $NetAdd = $null
            }
            Process {
                $BinaryIP = ConvertTo-BinaryIP $IP
                $BinaryMask = ConvertTo-BinaryIP $Mask
                0..34 | %{
                    $IPBit = $BinaryIP.Substring($_,1)
                    $MaskBit = $BinaryMask.Substring($_,1)
                    IF ($IPBit -eq '1' -and $MaskBit -eq '1') {
                        $NetAdd = $NetAdd + "1"
                    } elseif ($IPBit -eq ".") {
                        $NetAdd = $NetAdd +'.'
                    } else {
                        $NetAdd = $NetAdd + "0"
                    }
                }
                if ($Binary) {
                    return $NetAdd
                } else {
                    return ConvertFrom-BinaryIP $NetAdd
                }
            }
        }
       
        Function ConvertTo-BinaryIP {
            #.Synopsis
            # Convert an IP address to binary
            #.Example
            # ConvertTo-BinaryIP -IP 192.168.1.1
            Param (
                [string]
                $IP
            )
            Process {
                $out = @()
                ForEach ($octet in $IP.split('.')) {
                    $strout = $null
                    0..7|% {
                        IF (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                            $octet = $octet - [math]::pow(2,(7-$_))
                            [string]$strout = $strout + "1"
                        } else {
                            [string]$strout = $strout + "0"
                        }  
                    }
                    $out += $strout
                }
                return [string]::join('.',$out)
            }
        }
 
 
        Function ConvertFrom-BinaryIP {
            #.Synopsis
            # Convert from Binary to an IP address
            #.Example
            # Convertfrom-BinaryIP -IP 11000000.10101000.00000001.00000001
            Param (
                [string]
                $IP
            )
            Process {
                $out = @()
                ForEach ($octet in $IP.split('.')) {
                    $strout = 0
                    0..7|% {
                        $bit = $octet.Substring(($_),1)
                        IF ($bit -eq 1) {
                            $strout = $strout + [math]::pow(2,(7-$_))
                        }
                    }
                    $out += $strout
                }
                return [string]::join('.',$out)
            }
        }

        Function ConvertTo-MaskLength {
            #.Synopsis
            # Convert from a netmask to the masklength
            #.Example
            # ConvertTo-MaskLength -Mask 255.255.255.0
            Param (
                [string]
                $mask
            )
            Process {
                $out = 0
                ForEach ($octet in $Mask.split('.')) {
                    $strout = 0
                    0..7|% {
                        IF (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                            $octet = $octet - [math]::pow(2,(7-$_))
                            $out++
                        }
                    }
                }
                return $out
            }
        }
 
        Function ConvertFrom-MaskLength {
            #.Synopsis
            # Convert from masklength to a netmask
            #.Example
            # ConvertFrom-MaskLength -Mask /24
            #.Example
            # ConvertFrom-MaskLength -Mask 24
            Param (
                [int]
                $mask
            )
            Process {
                $out = @()
                [int]$wholeOctet = ($mask - ($mask % 8))/8
                if ($wholeOctet -gt 0) {
                    1..$($wholeOctet) |%{
                        $out += "255"
                    }
                }
                $subnet = ($mask - ($wholeOctet * 8))
                if ($subnet -gt 0) {
                    $octet = 0
                    0..($subnet - 1) | %{
                         $octet = $octet + [math]::pow(2,(7-$_))
                    }
                    $out += $octet
                }
                for ($i=$out.count;$i -lt 4; $I++) {
                    $out += 0
                }
                return [string]::join('.',$out)
            }
        }

        Function Get-IPRange {
            #.Synopsis
            # Given an Ip and subnet, return every IP in that lan segment
            #.Example
            # Get-IPRange -IP 192.168.1.36 -Mask 255.255.255.0
            #.Example
            # Get-IPRange -IP 192.168.5.55 -Mask /23
            Param (
                [string]
                $IP,
               
                [string]
                $netmask
            )
            Process {
                iF ($netMask.length -le 3) {
                    $masklength = $netmask.replace('/','')
                    $Subnet = ConvertFrom-MaskLength $masklength
                } else {
                    $Subnet = $netmask
                    $masklength = ConvertTo-MaskLength -Mask $netmask
                }
                $network = Get-NetworkAddress -IP $IP -Mask $Subnet
               
                [int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $network.split('.')
                $TotalIPs = ([math]::pow(2,(32-$masklength)) -2)
                $blocks = ($TotalIPs - ($TotalIPs % 256))/256
                if ($Blocks -gt 0) {
                    1..$blocks | %{
                        0..255 |%{
                            if ($FourthOctet -eq 255) {
                                If ($ThirdOctet -eq 255) {
                                    If ($SecondOctet -eq 255) {
                                        $FirstOctet++
                                        $secondOctet = 0
                                    } else {
                                        $SecondOctet++
                                        $ThirdOctet = 0
                                    }
                                } else {
                                    $FourthOctet = 0
                                    $ThirdOctet++
                                }  
                            } else {
                                $FourthOctet++
                            }
                            Write-Output ("{0}.{1}.{2}.{3}" -f `
                            $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                        }
                    }
                }
                $sBlock = $TotalIPs - ($blocks * 256)
                if ($sBlock -gt 0) {
                    1..$SBlock | %{
                        if ($FourthOctet -eq 255) {
                            If ($ThirdOctet -eq 255) {
                                If ($SecondOctet -eq 255) {
                                    $FirstOctet++
                                    $secondOctet = 0
                                } else {
                                    $SecondOctet++
                                    $ThirdOctet = 0
                                }
                            } else {
                                $FourthOctet = 0
                                $ThirdOctet++
                            }  
                        } else {
                            $FourthOctet++
                        }
                        Write-Output ("{0}.{1}.{2}.{3}" -f `
                        $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                    }
                }
            }
        }
    }
    Process {
        #get every ip in scope
        Get-IPRange $IP $netmask | %{
        [void]$IPs.Add($_)
        }
        $Script:IPList = $IPs
    }
}

# ==============================================================================
# Function Name 'SingleEntry' - Enumerates Computer from user input
# ==============================================================================
Function SingleEntry 
{
    $Comp = Read-Host "Enter Computer Name or IP (1.1.1.1) or IP Subnet (1.1.1.1/24)"
    If ($Comp -eq $Null) { . SingleEntry } 
    ElseIf ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
    {
        $Temp = $Comp.Split("/")
        $IP = $Temp[0]
        $Mask = $Temp[1]
        . Get-Subnet-Range $IP $Mask
        $Script:Computers = $Script:IPList
    }
    Else
    { $Script:Computers = $Comp}
}

Write-Host "  ____      ____  _   _     _____  _    ____ ___   ____    _  _____  " -ForegroundColor Green
Write-Host " |  _ \ ___/ ___|| | | |   |_   _|/ \  / ___/ _ \ / ___|  / \|_   _| " -ForegroundColor Green
Write-Host " | |_) / _ \___ \| |_| |_____| | / _ \| |  | | | | |     / _ \ | |   " -ForegroundColor Green
Write-Host " |  __/ (_) |__) |  _  |_____| |/ ___ \ |__| |_| | |___ / ___ \| |   " -ForegroundColor Green
Write-Host " |_|   \___/____/|_| |_|     |_/_/   \_\____\___/ \____/_/   \_\_|   " -ForegroundColor Green
Write-Host ""

mkdir .\PoSH_Tacocat--Results | Out-Null
mkdir .\PoSH_Tacocat--Results\connects | Out-Null
mkdir .\PoSH_Tacocat--Results\DLLs | Out-Null
Set-Location .\PoSH_Tacocat--Results

# Calling First and Second function to gain user input
First
Write-Host ""
Write-Host "Got computer list... Next task..." (Get-Date) -ForegroundColor Yellow
Right_Meow

# Function to find which computers user wants to enumerate.
Function First
{
Write-Host ""
Write-Host "How do you want to list computers?"	-ForegroundColor Yellow
$strResponse = Read-Host "`n[1] All Domain Computers (Must provide Domain), `n[2] Computer names from a File, `n[3] List a Single Computer manually `n"
If($strResponse -eq "1"){. ListComputers | Sort-Object}
	elseif($strResponse -eq "2"){. ListTextFile}
	elseif($strResponse -eq "3"){. SingleEntry}
	else{Write-Host "You did not supply a correct response, `
	Please run script again."; Pause -foregroundColor Red}	
}

# Fcuntion to select what data user wants to enumerate from selected computers.
Function Right_Meow
{			
While ($strResponse2 -ne 21)
    {
        Write-Host ""
        Write-Host "Which function would you like to run?" -ForegroundColor Yellow
        $strResponse2 = Read-Host "`n[1] All Functions `n[2] Autoruns `n[3] NetLogon `n[4] EventLogs (Disabled) `n[5] Drivers `n[6] Mapped Drives `n[7] Processes/Connections `n[8] DLLs/Hashes `n[9] Scheduled Tasks `n[10] Services `n[11] Environment Variables `n[12] Users `n[13] Groups `n[14] Logged on Users `n[15] Network Config `n[16] Shares `n[17] Disk Info `n[18] System Info `n[19] Installed Patches `n[20] Installed Software (Disabled) `n[21] Exit `n"
        # Functions that are disabled are commented out in action 1 and also in the function.
        If($strResponse2 -eq "1"){Write-Host "Running All Functions..." (Get-Date) -ForegroundColor Yellow
                                  . Autoruns
                                    Netlogon
                                    #EventLogs
                                    Drivers
                                    Mapped_Drives
                                    Connections
				                    DLLs
                                    Scheduled_Tasks
                                    Services
                                    Environment_Variables
                                    Users
                                    Groups
                                    Logged_On_Users
                                    Network_Configs
                                    Shares
                                    Disk
                                    System_Info
                                    Patches
                                    #Software
				 }
            elseif($strResponse2 -eq "2"){. Autoruns}
            elseif($strResponse2 -eq "3"){. Netlogon}
            elseif($strResponse2 -eq "4"){. EventLogs}
            elseif($strResponse2 -eq "5"){. Drivers}
            elseif($strResponse2 -eq "6"){. Mapped_Drives}
            elseif($strResponse2 -eq "7"){. Connections}
	        elseif($strResponse2 -eq "8"){. DLLs}
            elseif($strResponse2 -eq "9"){. Scheduled_Tasks}
            elseif($strResponse2 -eq "10"){. Services}
            elseif($strResponse2 -eq "11"){. Environment_Variables}
            elseif($strResponse2 -eq "12"){. Users}
            elseif($strResponse2 -eq "13"){. Groups}
            elseif($strResponse2 -eq "14"){. Logged_On_Users}
            elseif($strResponse2 -eq "15"){. Network_Configs}
            elseif($strResponse2 -eq "16"){. Shares}
            elseif($strResponse2 -eq "17"){. Disk}
            elseif($strResponse2 -eq "18"){. System_Info}
            elseif($strResponse2 -eq "19"){. Patches}
            elseif($strResponse2 -eq "20"){. Software}
    }
}

# ==============================================================================
# Autorun information
# ==============================================================================
Function Autoruns
{
Write-Host "Retrieving Autoruns information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_StartupCommand -ComputerName $computers | Select-Object PSComputerName, Name, Location, Command, User | Export-CSV ./Autoruns.csv -NoTypeInformation
}

# ==============================================================================
# Logon information
# ==============================================================================
Function NetLogon
{
Write-Host "Retrieving logon information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName $computers | Select-Object PSComputerName, Name, LastLogon, LastLogoff, NumberOfLogons, PasswordAge | Export-CSV .\NetLogon.csv -NoTypeInformation
}

# ==============================================================================
# Event log information (Note: If logs are not returning data, ensure the script 
# is not ran from the ISE console)
# ==============================================================================
#Function Eventlogs
#{
#Write-Host "Retrieving event log information..." (Get-Date) -ForegroundColor Yellow
#Get-WmiObject -Class Win32_NTLogEvent -ComputerName $computers | Where-Object {$_.LogFile -eq 'System'} | Select-Object PSComputerName, LogFile, EventCode, TimeGenerated, Message, InsertionStrings, Type | Select-Object -first 50 | Export-CSV .\Eventlogs-System.csv -NoTypeInformation
#Get-WmiObject -Class Win32_NTLogEvent -ComputerName $computers | Where-Object {$_.LogFile -eq 'Security'} | Select-Object PSComputerName, LogFile, EventCode, TimeGenerated, Message, InsertionStrings, Type | Select-Object -first 50 | Export-CSV .\Eventlogs-Security.csv -NoTypeInformation
#Get-WmiObject -Class Win32_NTLogEvent -ComputerName $computers | Where-Object {$_.LogFile -eq 'Application'} | Select-Object PSComputerName, LogFile, EventCode, TimeGenerated, Message, InsertionStrings, Type | Select-Object -first 50 | Export-CSV .\Eventlogs-Application.csv -NoTypeInformation
#}

# ==============================================================================
# Driver information
# ==============================================================================
Function Drivers
{
Write-Host "Retrieving driver information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_SystemDriver -ComputerName $computers | Select-Object PSComputerName, Name, InstallDate, DisplayName, PathName, State, StartMode | Export-CSV .\Drivers.csv -NoTypeInformation
}

# ==============================================================================
# Mapped drives information
# ==============================================================================
Function Mapped_Drives
{
Write-Host "Retrieving mapped drives information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_MappedLogicalDisk -ComputerName $computers | Select-Object PSComputerName, Name, ProviderName | Export-CSV .\Mapped_Drives.csv -NoTypeInformation
}

# ==============================================================================
# Process information
# Network connections
# Combining network connection files
# ==============================================================================
Function Connections
{
Write-Host "Retrieving running processes information..." (Get-Date) -ForegroundColor Yellow
Write-Host "Retrieving network connections..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_Process -ComputerName $computers | Select-Object PSComputerName, Name, Description, ProcessID, ParentProcessID, Handle, HandleCount, ThreadCount, CreationDate | Export-CSV .\Processes.csv -NoTypeInformation
ForEach($computer in $computers){
Set-Location .\connects
Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $computer -ArgumentList "cmd /c netstat -ano > c:\$computer.txt" > $null 2>&1
Start-Sleep -Seconds 10
Copy-Item \\$computer\c$\$computer.txt .\
Remove-Item \\$computer\c$\$computer.txt
$conn = Get-Content .\$computer.txt
$conn2 = $conn | ForEach {$computer + $_}
$conn2 | Select-Object -Skip 4 | Out-File .\$computer'_'.txt
Remove-Item .\$computer.txt
cd ..
}
Get-Content .\connects\*.txt | Out-File .\Connections.csv
# Replacing characters in the Connecions.csv for ease of ingection into Kibana. If not ingesting into Kibana comment out the next 5 lines.
$connections = Get-Content .\Connections.csv
$connections -Replace '\s\s+', "," | Set-Content .\Connections.csv
(Get-Content .\Connections.csv).Replace('[::]', "0.0.0.0") | Set-Content .\Connections.csv
(Get-Content .\Connections.csv).Replace('*;*', "0.0.0.0") | Set-Content .\Connections.csv
(Get-Content .\Connections.csv).Replace(':', ",") | Set-Content .\Connections.csv
Remove-Item .\connects -Recurse -Force
}

# ==============================================================================
# DLLs and Hashes
# ==============================================================================
Function DLLs {
# Creating script to push to remote computer for execution
{$results = Get-Process | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue | Sort-Object FileName -Unique | % {
		if ($_.FileName -ne $null) {
			$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
			$hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.IO.File]::ReadAllBytes($_.FileName)))
			$_ | Add-Member -MemberType NoteProperty SHA_1 $($hash -replace "-","")
            $authenticode = (Get-AuthenticodeSignature -FilePath $_.FileName | Select-Object Status).Status
            $_ | Add-Member -MemberType NoteProperty SignatureStatus $authenticode
		}
		else {
			$_ | Add-Member -MemberType NoteProperty SHA_1 $null
		}
		$_ | Add-Member -MemberType NoteProperty PSComputerName $env:COMPUTERNAME
		$_
		}
	   $results | Select-Object PSComputerName, ModuleName, FileName, SHA_1, SignatureStatus, Size, Company, Description, FileVersion, Product, ProductVersion | Export-CSV c:\$env:COMPUTERNAME.csv -NoTypeInformation} > .\DLLs.ps1	

    Write-Host "Retrieving DLL and Hash information..." (Get-Date) -ForegroundColor Yellow
	ForEach ($computer in $computers) {
    Copy-Item .\DLLs.ps1 \\$computer\c$
    Set-Location .\DLLs
    #Setting registy keys to allow for PS ExecutionPolicy change to allow DLLs.ps1 to exectute on remote computer
    Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $computer -ArgumentList "PowerShell.exe /c Remove-Item -Path HKCU:\Software\Microsoft\PowerShell -Force" > $null 2>&1
    Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $computer -ArgumentList "PowerShell.exe /c Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name ExecutionPolicy -Value Unrestricted -Force" > $null 2>&1
    #Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $computer -ArgumentList "PowerShell.exe /c Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force" > $null 2>&1
	Start-Sleep -Seconds 10
    Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $computer -ArgumentList "PowerShell.exe /c c:\DLLs.ps1" > $null 2>&1
    Start-Sleep -Seconds 20
    Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $computer -ArgumentList "PowerShell.exe /c Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name ExecutionPolicy -Value Restricted -Force" > $null 2>&1
    #Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $computer -ArgumentList "PowerShell.exe /c Set-ExecutionPolicy -ExecutionPolicy Restricted -Force" > $null 2>&1
    Copy-Item \\$computer\c$\$computer.csv .\
    Remove-Item \\$computer\c$\$computer.csv
    Remove-Item \\$computer\c$\DLLs.ps1
    cd ..
	}
    # Combining CSV files into one file
    $getFirstLine = $True
    Get-ChildItem .\DLLs\*.csv | ForEach {
        $filePath = $_
        $lines = Get-Content $filePath
        $linesToWrite = switch($getFirstLine) {
            $true {$lines}
            $false {$lines | Select-Object -Skip 1}
        }
        $getFirstLine = $false
        Add-Content .\DLLs.csv $linesToWrite
        }
    Remove-Item .\DLLs -Recurse -Force
    Remove-Item .\DLLs.ps1 -Recurse -Force
}

# ==============================================================================
# Scheduled tasks
# ==============================================================================
Function Scheduled_Tasks
{
Write-Host "Retrieving scheduled tasks created by at.exe or Win32_ScheduledJob..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_ScheduledJob -ComputerName $computers | Select-Object PSComputerName, Name, Owner, JodID, Command, RunRepeatedly, InteractWithDesktop | Export-CSV .\Scheduled_Tasks.csv -NoTypeInformation
}

# ==============================================================================
# Services
# ==============================================================================
Function Services
{
Write-Host "Retrieving service information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_Service -ComputerName $computers | Select-Object PSComputerName, ProcessID, Name, Description, PathName, Started, StartMode, StartName, State | Export-CSV .\Services.csv -NoTypeInformation
}

# ==============================================================================
# Environment variables
# ==============================================================================
Function Environment_Variables
{
Write-Host "Retrieving environment variables information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_Environment -ComputerName $computers | Select-Object PSComputerName, UserName, Name, VariableValue | Export-CSV .\Environment_Variables.csv -NoTypeInformation
}

# ==============================================================================
# User information
# ==============================================================================
Function Users
{
Write-Host "Retrieving user information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_UserAccount -ComputerName $computers | Select-Object PSComputerName, AccountType, Name, FullName, Domain, Disabled, LocalAccount, Lockout, PasswordChangeable, PasswordExpires, Sid | Export-CSV .\Users.csv -NoTypeInformation
}

# ==============================================================================
# Group information
# ==============================================================================
Function Groups
{
Write-Host "Retrieving group information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_Group -ComputerName $computers | Select-Object PSComputerName, Caption, Domain, Name, Sid | Export-CSV .\Groups.csv -NoTypeInformation
}

# ==============================================================================
# Logged in user
# ==============================================================================
Function Logged_On_Users
{
Write-Host "Retrieving loggedon user information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computers | Select-Object PSComputerName, Username | Export-CSV .\Logged_on_User.csv -NoTypeInformation
}

# ==============================================================================
# Network settings
# ==============================================================================
Function Network_Configs
{
Write-Host "Retrieving network configurations..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $computers | Select-Object PSComputerName, IPAddress | Export-CSV .\Network_Configs.csv -NoTypeInformation
#Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $computers | Select-Object PSComputerName, IPAddress, IPSubnet, DefaultIPGateway, DHCPServer, DNSHostname, DNSserversearchorder, MACAddress, description | Export-CSV .\Network_Configs.csv -NoTypeInformation
}

# ==============================================================================
# Shares
# ==============================================================================
Function Shares
{
Write-Host "Retrieving shares information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_Share -ComputerName $computers | Select-Object PSComputerName, Name, Path, Description | Export-CSV .\Shares.csv -NoTypeInformation
}

# ==============================================================================
# Disk information
# ==============================================================================
Function Disk
{
Write-Host "Retrieving disk information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_LogicalDisk -ComputerName $computers | Select-Object PSComputerName, DeviceID, Description, ProviderName | Export-CSV .\Disk.csv -NoTypeInformation
}

# ==============================================================================
# System information
# ==============================================================================
Function System_Info
{
Write-Host "Retrieving system information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computers | Select-Object PSComputerName, Domain, Model, Manufacturer, EnableDaylightSavingsTime, PartOfDomain, Roles, SystemType, NumberOfProcessors, TotalPhysicalMemory, Username | Export-CSV .\System_Info.csv -NoTypeInformation
}

# ==============================================================================
# Patch information
# ==============================================================================
Function Patches
{
Write-Host "Retrieving installed patch information..." (Get-Date) -ForegroundColor Yellow
Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $computers | Select-Object PSComputerName, HotFixID, Description, InstalledBy, InstalledOn | Export-CSV .\Patches.csv -NoTypeInformation
}

# ==============================================================================
# Installed Software... Warning: https://gregramsey.net/2012/02/20/Win32_product-is-evil/
# ==============================================================================
#Function Software
#{
#Write-Host "Retrieving installed software information..." (Get-Date) -ForegroundColor Yellow
#Get-WmiObject -Class Win32_Product -ComputerName $computers | Select-Object PSComputerName, Name, PackageCache, Vendor, Version, IdentifyingNumber | Export-CSV .\Software.csv -NoTypeInformation
#}

Write-Host "Completed at..." (Get-Date) -ForegroundColor Yellow