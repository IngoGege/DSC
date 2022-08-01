<#

.SYNOPSIS

Created by: https://ingogegenwarth.wordpress.com/
Version:    42 ("What do you get if you multiply six by nine?")
Changed:    14.09.2014

.LINK
http://www.get-blog.com/?p=189
http://learn-powershell.net/2012/05/13/using-background-runspaces-instead-of-psjobs-for-better-performance/
https://msdn.microsoft.com/powershell/dsc/troubleshooting

.DESCRIPTION

This script allows you to trigger a consistency check on target nodes. Besides this you can stop the WmiPrvSE process and clear DSC related caches. The script is able to run multithreaded.

.PARAMETER Computername

 A single computer or an array of computernames. This parameter supports pipeline.

.PARAMETER Credential

Credential to be used to connect to the remote computer.

.PARAMETER KillWmiPrvSE

This will try to stop the WmiPrvSE process, which is responsible for the DSC engine, before it triggers the consistency check.

.PARAMETER MultiThread

By default multiple computers will be processed sequential. Use this switch to process all computers in parallel.

.PARAMETER OperationTimeoutSec

The time until the command Invoke-CimMethod runs into a timeout against the remote computer.

.PARAMETER Threads

 If MultiThread is used this defines the maximum number of parallel threads.

.PARAMETER MaxResultTime

If MultiThread is used this defines the time a check must complete. Default is 240.

.EXAMPLE 

Enforce the consistency check against multiple computers
.\Enforce-DSCConfiguration.ps1 -Computername fabex01,fabex02 -Verbose

Enforce the consistency check against multiple computers, stop the WmiPrvSE process, clear the cache and run the script mutithreaded
.\Enforce-DSCConfiguration.ps1 -Computername fabex01,fabex02 -Verbose -MultiThread -KillWmiPrvSE -ClearCache

Pipeline objects into the script
Get-ADComputer -Filter { msExchCapabilityIdentifiers -eq '1'} | select DNSHostName | .\Enforce-DSCConfiguration.ps1 -Verbose -MultiThread
#>

[cmdletbinding()]
param (
    [Parameter( Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True, Position=0)]
    [Alias('Fqdn','DNSHostName','ServerName','Name','Computer')]
    [string[]]$Computername,
    
    [Parameter( Mandatory=$False, Position=1)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [parameter( Mandatory=$false, Position=2)]
    [switch]$KillWmiPrvSE,

    [parameter( Mandatory=$false, Position=3)]
    [switch]$ClearCache,
    
    [parameter( Mandatory=$false, Position=4)]
    [switch]$MultiThread,
    
    [Parameter( Mandatory=$False, Position=5)]
    [int]$OperationTimeoutSec = 0,
    
    [parameter( Mandatory=$false, Position=6)]
    [ValidateRange(0,20)]
    [int]$Threads= '15',
    
    [parameter( Mandatory=$false, Position=7)]
    [int]$MaxResultTime='240'
)
Begin {
$Results = @()

#initiate runspace and make sure we are using single-threaded apartment STA
$Jobs = @()
$Sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $Threads,$Sessionstate, $Host)
$RunspacePool.ApartmentState = "STA"
$RunspacePool.Open()
[int]$j='1'

function EnforceDSCConfiguration {
[cmdletbinding()]
param (
    [Parameter(Mandatory=$True, Position=0)]
    [Alias('Fqdn','DNSHostName','ServerName','Name','Computer')]
    [string[]]$Computername,
    
    [Parameter(Mandatory=$False, Position=1)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$False, Position=2)]
    [Int]$OperationTimeoutSec = 0,

    [switch]$KillWmiPrvSE,

    [switch]$ClearCache
    )
function KillWmiPrvSE {
[cmdletbinding()]
param (
    [string[]]$Computername,
    [System.Management.Automation.PSCredential]$Credential,
    [Int]$OperationTimeoutSec = 0
)
#$ScriptBlock = {Get-Process -Name WmiPrvSE | Stop-Process -Confirm:$false -Force | Out-Null}
$ScriptBlock = {
    $ProcID= Get-WmiObject msft_providers | Where-Object {$_.provider -like 'dsccore'} | Select-Object -ExpandProperty HostProcessIdentifier
    If ($ProcID) {
        Get-Process -ID $ProcID| Stop-Process -Confirm:$false -Force | Out-Null
    }
    }

ForEach ($Computer in $Computername) {
Write-Verbose "Will terminate all WmiPrvSE processes on computer:$($Computer)"
    If ($Credential -eq $null) {
        $currentuser = $Env:USERNAME
        Write-Verbose "No credential given. Using logged on user: $($currentuser)"
        try {
            Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $Computer -ErrorAction Stop
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    Else {
        Write-Verbose "Using given credentials $($Credential.Username)"
        try {
            Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $Computer -Credential $Credential -ErrorAction Stop
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
}
}

function ClearDSCFileCache {
[cmdletbinding()]
param (
    [string[]]$Computername,
    [System.Management.Automation.PSCredential]$Credential
)
$ScriptBlock = {Get-ChildItem $env:Windir\System32\Configuration\BuiltinProvCache -Filter *.cache -Recurse | Remove-Item -Force}
ForEach ($Computer in $Computername) {
Write-Verbose "Will delete all caches of DSC on computer:$($Computer)"
    If ($Credential -eq $null) {
        $currentuser = $Env:USERNAME
        Write-Verbose "No credential given. Using logged on user: $($currentuser)"
        try {
            Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $Computer -ErrorAction Stop
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    Else {
        Write-Verbose "Using given credentials $($Credential.Username)"
        try {
            Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $Computer -Credential $Credential -ErrorAction Stop
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
}
}

If ($KillWmiPrvSE -eq $true) {
    KillWMIPrvSE -Computername $Computername -Credential $Credential
}

If ($ClearCache -eq $true) {
    ClearDSCFileCache -Computername $Computername -Credential $Credential
}

#create hashtable of parameters
$params = @{
Namespace = 'root/Microsoft/Windows/DesiredStateConfiguration'
ClassName = 'MSFT_DSCLocalConfigurationManager'
MethodName = 'PerformRequiredConfigurationChecks'
Arguments = @{  Flags = [uint32] 1  } }

ForEach ($Computer in $Computername) {
Write-Verbose "Working on computer:$($Computer)"
    If ($Credential -eq $null) {
        $currentuser = $Env:USERNAME
        Write-Verbose "No credential given. Using logged on user: $($currentuser)"
        try {
            $Session = New-CimSession -ComputerName $Computer -ErrorAction Stop
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    Else {
        Write-Verbose "Using given credentials $($Credential.Username)"
        try {
            $Session = New-CimSession -ComputerName $Computer -Credential $Credential -ErrorAction Stop
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    try {
        Invoke-CimMethod @params -CimSession $Session -ErrorAction Stop -OutVariable result -OperationTimeoutSec $OperationTimeoutSec
    }
    catch {
        Write-Warning $_.Exception.Message
    }
}
}

}

Process {

#if multi-threaded create jobs
If ($MultiThread) {
    #create scriptblock from function
    $ScriptBlock = [scriptblock]::Create((Get-ChildItem Function:\EnforceDSCConfiguration).Definition)
    ForEach($Computer in $Computername) {
        try{
            $PowershellThread = [powershell]::Create() #.AddScript($ScriptBlock).AddParameter('Computername',$Computer)
            If ($PSBoundParameters.ContainsKey('Verbose')){
                #Write-Verbose "MultiThreads Verbose exists!"
                $PowershellThread.AddScript({$VerbosePreference = 'Continue'}) | Out-Null
            }
            $PowershellThread.AddScript($ScriptBlock).AddParameter('Computername',$Computer) | Out-Null
            If ($Credential) {
                $PowershellThread.AddParameter('Credential',$Credential) | Out-Null
            }
            If ($KillWmiPrvSE) {
                $PowershellThread.AddParameter('KillWmiPrvSE',$KillWmiPrvSE) | Out-Null
            }
            If ($ClearCache) {
                $PowershellThread.AddParameter('ClearCache',$ClearCache) | Out-Null
            }
            $PowershellThread.AddParameter('OperationTimeoutSec',$OperationTimeoutSec) | Out-Null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Computer
            $Jobs += $Job
        }
        catch {
            #$Error[0].Exception
            $_.Exception.Message
        }
    }
}
Else {
    $Results += EnforceDSCConfiguration -Computername $Computername -Credential $Credential -OperationTimeoutSec $OperationTimeoutSec -KillWmiPrvSE:$KillWmiPrvSE -ClearCache:$ClearCache
}

}

End {
#monitor and retrieve the created jobs
If ($MultiThread) {
    $SleepTimer = 200
    $ResultTimer = Get-Date
    While (@($Jobs | Where-Object {$_.Handle -ne $Null}).count -gt 0)  {
    $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
        If ($Remaining.Length -gt 60){
            $Remaining = $Remaining.Substring(0,60) + "..."
        }
        Write-Progress `
            -Activity "Waiting for Jobs - $($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running" `
            -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
            -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $Remaining"

        ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True})){
            Write-Progress `
            -Activity "Waiting for Jobs - $($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running" `
            -Status "Ready" `
            -Completed
            $Results += $Job.Thread.EndInvoke($Job.Handle)
            $Job.Thread.Dispose()
            $Job.Thread = $Null
            $Job.Handle = $Null
            $ResultTimer = Get-Date
        }
        If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxResultTime){
            Write-Warning "Child script appears to be frozen for $($Job.Object), try increasing MaxResultTime"
            #Exit
        }
        Start-Sleep -Milliseconds $SleepTimer
    # kill all incomplete threads when hit "CTRL+q"
    If ($Host.UI.RawUI.KeyAvailable) {
        $KeyInput = $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho")
        If (($KeyInput.ControlKeyState -cmatch '(Right|Left)CtrlPressed') -and ($KeyInput.VirtualKeyCode -eq '81')) {
            Write-Host -fore red "Kill all incomplete threads....."
                ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})){
                    Write-Host -fore yellow "Stopping job $($Job.Object) ...."
                    $Job.Thread.Stop()
                    $Job.Thread.Dispose()
                    Write-Progress `
                        -id 1 `
                        -Activity "Waiting for Jobs - $($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running" `
                        -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
                        -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $Remaining"
                }
            Write-Host -fore red "Exit script now!"
            Exit
        }
    }
    }
    # clean-up
    $RunspacePool.Close() | Out-Null
    $RunspacePool.Dispose() | Out-Null
    [System.GC]::Collect()
}
$Results | select @{l="Computer";e={$_.PSComputerName}},@{l="Result";e={$_.ReturnValue}}
}