@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Script dir
cd /d "%~dp0"

:: Execute Powershell (.ps1) files alphabetically (non-blocking)
for /f "tokens=*" %%A in ('dir /b /o:n *.ps1') do (
    Start "" powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "%%A"
)

:: Execute Registry (.reg) files alphabetically
for /f "tokens=*" %%C in ('dir /b /o:n *.reg') do (
    reg import "%%C"
)

:: Perms
takeown /f %windir%\System32\Oobe\useroobe.dll /A
icacls %windir%\System32\Oobe\useroobe.dll /reset
icacls %windir%\System32\Oobe\useroobe.dll /inheritance:r

takeown /f C:\Windows\System32\wbem\WmiPrvSE.exe /A
icacls C:\Windows\System32\wbem\WmiPrvSE.exe /reset
icacls C:\Windows\System32\wbem\WmiPrvSE.exe /inheritance:r

takeown /f C:\Windows\System32\wbem\Wmiadap.exe /A
icacls C:\Windows\System32\wbem\Wmiadap.exe /reset
icacls C:\Windows\System32\wbem\Wmiadap.exe /inheritance:r

takeown /f C:\Windows\System32\dllhost.exe /A
icacls C:\Windows\System32\dllhost.exe /reset
icacls C:\Windows\System32\dllhost.exe /inheritance:r

takeown /f C:\Windows\System32\conhost.exe /A
icacls C:\Windows\System32\conhost.exe /reset
icacls C:\Windows\System32\conhost.exe /inheritance:r

takeown /f %windir%\system32\consent.exe /A
icacls %windir%\system32\consent.exe /reset
icacls %windir%\system32\consent.exe /inheritance:r
icacls %windir%\system32\consent.exe /grant:r "Console Logon":RX

takeown /f %windir%\System32\winmm.dll /A
icacls %windir%\System32\winmm.dll /reset
icacls %windir%\System32\winmm.dll /inheritance:r
icacls %windir%\System32\winmm.dll /grant:r "Console Logon":RX

:: UAC
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f

:: Services
sc config VNC start= disabled
sc stop VNC
sc config FileZilla Server start= disabled
sc stop FileZilla Server
sc config OpenSSH start= disabled
sc stop OpenSSH
sc config vsftpd start= disabled
sc stop vsftpd
sc config TeamViewer start= disabled
sc stop TeamViewer
sc config AnyDesk start= disabled
sc stop AnyDesk
sc config LogMeIn start= disabled
sc stop LogMeIn
sc config Radmin start= disabled
sc stop Radmin
sc config SsdpSrv start= disabled
sc stop SsdpSrv
sc config upnphost start= disabled
sc stop upnphost
sc config TelnetServer start= disabled
sc stop TelnetServer
sc config sshd start= disabled
sc stop sshd
sc config ftpsvc start= disabled
sc stop ftpsvc
sc config seclogon start= disabled
sc stop seclogon
sc config LanmanWorkstation start= disabled
sc stop LanmanWorkstation
sc config LanmanServer start= disabled
sc stop LanmanServer
sc config WinRM start= disabled
sc stop WinRM
sc config RemoteRegistry start= disabled
sc stop RemoteRegistry
sc config SNMP start= disabled
sc stop SNMP

:: Bios tweak
%windir%\system32\bcdedit.exe /set nx AlwaysOn

:: Users
net user defaultuser0 /delete

:: Label
label C: Windows

:: Bufferbloat
netsh int tcp set global autotuninglevel=restricted

:: Security Policy
lgpo /s GSecurity.inf

:: Restart
shutdown /r /t 0