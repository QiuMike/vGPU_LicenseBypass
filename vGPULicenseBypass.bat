@ECHO off
@setlocal EnableDelayedExpansion
@set "params=%*"
@cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )
@set LF=^


@color 17
@SET command=#
@FOR /F "tokens=*" %%i in ('findstr -bv @ "%~f0"') DO SET command=!command!!LF!%%i
@powershell -noprofile -command !command! & goto:eof

# *** POWERSHELL CODE STARTS HERE *** #

    Write-Host 'Nvidia vGPU License bypass with help from the wonderful vGPU_Unlock community.'
    Write-Host '----------------------------------------------'
    Write-Host 'Nvidia vGPU is property of NVIDIA Corporation.'
    Write-Host ''
    sleep 1

    $RegistryPath = 'HKLM:\SOFTWARE\NVIDIA Corporation\Global\GridLicensing'
    $RegistryProps = @(
        @{
            Name         = 'UnlicensedUnrestrictedStateTimeout'
            PropertyType = 'DWORD'
            Value        = 0x5a0
        }
        @{
            Name         = 'UnlicensedRestricted1StateTimeout'
            PropertyType = 'DWORD'
            Value        = 0x5a0
        }
        @{
            Name         = 'DisableExpirationPopups'
            PropertyType = 'DWORD'
            Value        = 1
        }
        @{
            Name         = 'DisableSpecificPopups'
            PropertyType = 'DWORD'
            Value        = 1
        }
    )

    # Get login account and check if it is the administrator or not
	function check_login{
	    $output = whoami /all
        $IsAdministrator = $false

        foreach($line in $output){
            if ($line -like '*BUILTIN\Administrators*'){
                $IsAdministrator = $true
                break;
            }
        }

        return $IsAdministrator
    }
    # Get the default Admin account
    function Get-SWLocalAdmin {
        $computer = "Get-WMIObject  Win32_ComputerSystem"
        $ComputerName = $computer.name
        Try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $ComputerName)
                $UserPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($PrincipalContext)
                $Searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher
                $Searcher.QueryFilter = $UserPrincipal
                $Searcher.FindAll() | Where-Object {$_.Sid -Like '*-500'}
        } Catch {
                Write-Warning -Message "$($_.Exception.Message)"
        }
    }
    
    $time = '3AM'
    $taskName = 'Restart vGPU Driver'
    $taskDescr = "'Restart Nvidia vGPU device drivers daily at $time'"
    $taskScript = ('"& { Get-PnpDevice -Class Display -FriendlyName NVIDIA* -Status Error,OK | Foreach-Object -Process { Disable-PnpDevice -confirm:$false -InstanceId $_.InstanceId; Start-Sleep -Seconds 5; Enable-PnpDevice -confirm:$false -InstanceId $_.InstanceId } }"')

    try {
        Write-Host 'We will start by changing the unlicensed time from 20 mins to 1440 mins (1 day) with some registry keys'
        # Make sure the registry key path exists
        (New-Item -ItemType Directory -Path $RegistryPath -Force -ErrorAction SilentlyContinue | Out-Null)
        # Add/overwrite the properties
        foreach ($RegistryProp in $RegistryProps) { New-ItemProperty -Path $RegistryPath @RegistryProp -Force -InformationAction SilentlyContinue | Out-Null}
        Write-Host 'Done, continuing.' -Fore red
        Write-Host ''

        # Check if the task already exists; removes if present.
        Write-Output -InputObject ('Checking for existing Nvidia driver restart task and removing if present...')
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Output -InputObject ('Found and unregistered existing Nvidia driver restart task.')
            Write-Output ''
        }

        # Create the driver restart task.
        if ("check_login" == $true){
            # we assume that $env:username is the same as whoami
            $UserName = $env:username
        } else {
            # this will lead some issue that the login account is not the internal Administrator
            $UserName = "Get-SWLocalAdmin"
        }
        Write-Output -InputObject ('Adding new scheduled task "{0}", with user account "{1}", every day at "{2}"...' -f $taskName,$UserName,$time)
	$Principal = New-ScheduledTaskPrincipal -UserID $UserName -RunLevel Highest -LogonType S4U
        $taskTrigger = New-ScheduledTaskTrigger -Daily -At $time
        $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-WindowStyle Hidden -NonInteractive -NoProfile -Command {0} ' -f $taskScript)
        $task = Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Description $taskDescr
		# we seperate the Principal ops for there may be some permission issues, so we could work if user in login status
        Set-ScheduledTask -TaskName $taskName -Principal $Principal
        Write-Output -InputObject ('Registered scheduled task "{0}"' -f $task.TaskName)
    } catch {
        throw $PSItem
    } finally {
        Write-Host 'Done.' -Fore red
    }

Write-Host ''
Write-Host 'Restarting vGPU drivers in 3 seconds. Please be patient, your screen may temporarily flash.'
sleep 3
Get-PnpDevice -Class Display -FriendlyName NVIDIA* -Status Error,OK | Foreach-Object -Process { Disable-PnpDevice -confirm:$false -InstanceId $_.InstanceId; Start-Sleep -Seconds 5; Enable-PnpDevice -confirm:$false -InstanceId $_.InstanceId}

Write-Host ''
Write-Host '(C) 2021'
Write-Host ''
sleep 1
Write-Host 'Completed, enjoy your free vGPU before Nvidia patches it!' -Fore red
Write-Host ''
Write-Host 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
exit
