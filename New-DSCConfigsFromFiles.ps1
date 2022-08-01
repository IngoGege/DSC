<#

.SYNOPSIS

Created by: https://ingogegenwarth.wordpress.com/
Version:    42 ("What do you get if you multiply six by nine?")
Changed:    14.09.2016

.LINK

.DESCRIPTION

This script will create MOF files and publish them to a pull server out of given Configuration, Environment Data and a custom CSV file, which must contain a column called ServerName

.PARAMETER ServerCSVFile

Full path to the CSV file containing the nodes

.PARAMETER DSCConfig

Path to your DSC Configuration file

.PARAMETER DSCConfigSettings

Path to your DSC Environment Data file

.PARAMETER MOFsPath

Path to a folder to store the generated MOF files

.PARAMETER CertPath

Path to a folder where all the certificates will be stored

.PARAMETER MOFsTargetPath

Path to the folder on the pull server to publish the files. Default is 'C:\Program Files\WindowsPowerShell\DscService\Configuration'

.PARAMETER PublishToPull

Switch to publish the files to the folder defined in MOFsTargetPath. Default is $true

.PARAMETER SkipPing

By default the script uses Test-Connection to check the availability of a node. If you use this switch this test will be bypassed. Default is $false

.PARAMETER SkipCert

Switch to bypass the certificate export. This is useful when you are using the same certificate on all nodes. Note: If you are going not to encrypt your credentials, make sure you have set the property PSDscAllowPlainTextPassword to $true!

.Parameter SkipCertVerification

If set to $true the verification of the certificate will be skipped, which speed-up the process.

.EXAMPLE 

.\New-DSCConfigsFromFiles.ps1 -ServerCSVFile C:\DSC\CSVs\LabServers.csv -DSCConfig C:\DSC\Scripts\DemoConfig.ps1 -DSCConfigSettings C:\DSC\Scripts\DemoConfig-Config.psd1 -MOFsPath C:\DSC\Config -CertPath C:\DSC\Certs -PublishToPull -SkipPing -Verbose

.NOTES
#>

[cmdletbinding()]
param(
    [ValidateScript({If (Test-Path $_ -PathType Leaf) {$True} Else {Throw "No file could not be found!"}})]
    [parameter( Mandatory=$true, Position=0)]
    [string]$ServerCSVFile,

    [ValidateScript({If (Test-Path $_ -PathType Leaf) {$True} Else {Throw "No file could not be found!"}})]
    [parameter( Mandatory=$false, Position=1)]
    [string]$DSCConfig,

    [ValidateScript({If (Test-Path $_ -PathType Leaf) {$True} Else {Throw "No file could not be found!"}})]
    [parameter( Mandatory=$false, Position=2)]
    [string]$DSCConfigSettings,
    
    [ValidateScript({If (Test-Path $_ -PathType Container) {$True} Else {Throw "Target folder for MOFs could not be found!"}})]
    [parameter( Mandatory=$false, Position=3)]
    [string]$MOFsPath = "C:\DSC\Config",

    [parameter( Mandatory=$false, Position=4)]
    [ValidateScript({If (Test-Path $_ -PathType Container) {$True} Else {Throw "Folder for certificates could not be found!"}})]
    [string]$CertPath = "C:\DSC\Certs",

    [parameter( Mandatory=$false, Position=5)]
    [ValidateScript({If (Test-Path $_ -PathType Container) {$True} Else {Throw "Target folder to publish MOFs could not be found!"}})]
    [string]$MOFsTargetPath = "C:\Program Files\WindowsPowerShell\DscService\Configuration",

    [parameter( Mandatory=$false, Position=6)]
    [switch]$PublishToPull = $true,

    [parameter( Mandatory=$false, Position=7)]
    [switch]$SkipPing=$true,

    [parameter( Mandatory=$false, Position=8)]
    [switch]$SkipCert,

    [parameter( Mandatory=$false, Position=9)]
    [boolean]$SkipCertVerification
)

Begin {

function Get-EncryptionCertificate
{
    [CmdletBinding()]
    param (
        [string]$ComputerName,
        [string]$Path,
        [switch]$DoExport,
        [boolean]$SkipCertVerify
    )
    If ($DoExport) {
    [array]$returnValue= Invoke-Command -ComputerName $computerName -ScriptBlock {
            if ($using:SkipCertVerify) {
                $certificates = dir Cert:\LocalMachine\my | sort NOTAFTER -Descending |
                                ?{$_.PrivateKey.KeyExchangeAlgorithm -and ($_.DnsNameList -match $env:ComputerName)} |
                                select -First 1
            }
            else {
                $certificates = dir Cert:\LocalMachine\my | sort NOTAFTER -Descending |
                                ?{$_.PrivateKey.KeyExchangeAlgorithm -and $_.Verify() -and ($_.DnsNameList -match $env:ComputerName)} |
                                select -First 1
            }
            $FW = (Get-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)").Enabled
            $Folder = $using:Path
            $Server = $using:Computername
            if ($certificates) {
                # Create the folder to hold the exported public key
                if (! (Test-Path $Folder)) {
                    md $Folder | Out-Null
                }
                #Enable FW
                If ($FW -eq "False") {
                    #Write-Host "Enable FW rule!"
                    Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"
                    #Sleep 2
                }
                # Export the public key to a well known location
                $certPath = Export-Certificate -Cert $certificates -FilePath (Join-Path -path $Folder -childPath "$Server.cer") -Force
                # Return the thumbprint, and exported certificate path
                return @($certificates.Thumbprint,$certPath);
            }
        }
    # Copy the exported certificate locally
    $destinationPath = join-path -Path "$Path" -childPath "$Computername.cer"
    Copy-Item -Path (join-path -path \\$Computername -childPath $returnValue[1].FullName.Replace(":","$"))  $destinationPath -Force | Out-Null
    }
    Else {
    [array]$returnValue= Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if ($using:SkipCertVerify) {
                $certificates = dir Cert:\LocalMachine\my | sort NOTAFTER -Descending |
                                ?{$_.PrivateKey.KeyExchangeAlgorithm -and ($_.DnsNameList -match $env:ComputerName)} |
                                select -First 1
            }
            else {
                $certificates = dir Cert:\LocalMachine\my | sort NOTAFTER -Descending |
                                ?{$_.PrivateKey.KeyExchangeAlgorithm -and $_.Verify() -and ($_.DnsNameList -match $env:ComputerName)} |
                                select -First 1
            }
            if ($certificates) {
                # Return the thumbprint
                return $certificates.Thumbprint;
            }
        }   
    }
    # Return the thumbprint, and exported certificate path
    return @($returnValue[0],$returnValue[1].FullName)
}

function PublishMOF
{
param (

    [parameter( Mandatory=$true, Position=0)]
    [string]$MOFFilePath,

    [parameter( Mandatory=$true, Position=1)]
    [string]$GUID,

    [parameter( Mandatory=$true, Position=2)]
    [string]$TargetFolder

)
$Destination = "$TargetFolder\$GUID.mof"
Copy-Item -Path $MOFFilePath -Destination $Destination -Force
New-DSCCheckSum -ConfigurationPath $Destination -OutPath $TargetFolder -Force
}

function ConvertTo-HashtableFromPsCustomObject
{ 
    param ( 
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [object[]]$psCustomObject 
    ); 
    process { 
        foreach ($myPsObject in $psCustomObject) { 
            $output = @{}; 
            $myPsObject | Get-Member -MemberType *Property | % { 
            $output.($_.name) = $myPsObject.($_.name); 
            } 
            $output; 
        }
    }
}

[string[]]$ComputerName
Write-Verbose "Import CSV file..."
$ComputerName = Import-Csv $ServerCSVFile | ?{$_.ServerName -notmatch 'Version'} #|Out-Null
Write-Verbose "Import Config from $($DSCConfig) ..."
#import Config
$Config = (Get-Content $DSCConfig | Out-String)
$Config = $Config.Substring('0',$Config.LastIndexOf('}')+1)
#execute expression
Write-Verbose "Invoke Config ..."
Invoke-Expression $Config
#get name of the Config to execute it later
$ConfigName = (dir function:* | ?{$_.commandtype -eq 'Configuration'} | select -First 1).Name
$ErrorActionPreference = "Stop"
}

Process {


ForEach ($Computer in $ComputerName) {
#create ConfigurationData
If ($DSCConfigSettings) {
    Write-Verbose "Create ConfigurationData from $($DSCConfigSettings) ..."
    $ConfigurationData = Invoke-Expression (Get-Content $DSCConfigSettings | Out-String)
}
Else {
    #create hashtable ConfigurationData
    Write-Verbose "Create ConfigurationData from scratch ..."
    $ConfigurationData = @{
        AllNodes = @();
        NonNodeData = ""
    }
}

$Name = $Computer.servername
Write-Host "Working on $($Name) ..."
#check availability
If ((!(Test-Connection -ComputerName $Name -Quiet -Count 1)) -and ($SkipPing -eq $false)) {
    Write-Host -ForegroundColor Red "Could not reach $($Name)! Will skip this one!"
    Continue
}
If (!($SkipCert -eq $true)) {
#get certificate data
try {
    Write-Verbose "Trying to retrieve Cert from node ..."
    $RemoteCert = Get-EncryptionCertificate -Computername $Name -DoExport -Path $CertPath -SkipCertVerify:$SkipCertVerification
    $TargetNodeCertID = $RemoteCert[0]
    $TargetNodeCertPath = $RemoteCert[1]
    Write-Verbose "Get Cert from Node with Thumbprint:$($TargetNodeCertID) and exported to $($TargetNodeCertPath) ..."
}
catch {
    Write-Host -fore red "Could not get cert from: $($Name)!`nException:`n$($_.Exception.Message)"
    Continue
}
}
#get GUID
Write-Verbose "Trying to get GUID from AD for $($Name) ..."
try {
    $GUID = ([guid]([adsisearcher]"(samaccountname=$Name`$)").FindOne().Properties["objectguid"][0]).Guid
}

catch {
    Write-Host -fore Yellow "No result from AD for: $($Name)!`nWill try with dNSHostName!"
}

If ($GUID -eq $Null) {
    try {
        #if NetBIOS fails try dNSHostname
        $GUID = ([guid]([adsisearcher]"(dNSHostName=$Name)").FindOne().Properties["objectguid"][0]).Guid
    }
    catch {
        Write-Host -fore Yellow "No result from AD for: $($Name)!`nWill skip this one!"
        Continue
    }
}

Write-Verbose "Found GUID:$($GUID) ..."
Write-Verbose "Build node hashtable from CSV import ..."
#create node hashtable
[hashtable]$tempHash = $computer | ConvertTo-HashtableFromPsCustomObject
$tempHash.Add("NodeName",$Name)

#set certificate data
If (!($SkipCert -eq $true)) {
    $tempHash.Add("CertificateFile",$TargetNodeCertPath)
    $tempHash.Add("Thumbprint",$TargetNodeCertID)
}

Write-Verbose "Add node hashtable for $($Name) to ConfigurationData ..."
#add node hashtable to ConfigurationData
$ConfigurationData.AllNodes = $ConfigurationData.AllNodes + $tempHash

try {
    Write-Verbose "Try to invoke command and build MOFs ..."
    $VerbosePreferenceBefore = $VerbosePreference
    $VerbosePreference = "SilentlyContinue"
    $SB = {param($ConfigurationData) &$ConfigName -OutputPath $MOFspath -ConfigurationData $ConfigurationData}
    Invoke-Command -ScriptBlock $SB -ArgumentList $ConfigurationData | Out-Null
    $VerbosePreference = $VerbosePreferenceBefore
    Write-Verbose "End of script ..."
}
catch {
    $_.Exception #.Message
}

#publish MOFs to pull server
If ($PublishToPull -eq $true) {
    Write-Verbose "Publish $("$MOFsPath\$Name.mof") with $GUID to $MOFsTargetPath ..."
    PublishMOF -MOFFilePath $("$MOFsPath\$Name.mof") -GUID $GUID -TargetFolder $MOFsTargetPath
}
}
}

End {
}
