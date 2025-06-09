@echo off
setlocal enabledelayedexpansion
color 0a
chcp 65001
title SYSTEM CONTROL TOOLKIT

:: Administrator rights check
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Administrator rights required! Please run as administrator.
    pause
    exit /b 1
)

:: Backup function
:BACKUP_CREATE
set "backup_dir=%~dp0backups"
if not exist "%backup_dir%" mkdir "%backup_dir%"
set "backup_file=%backup_dir%\system_backup_%date:~-4,4%%date:~-7,2%%date:~-10,2%.reg"
reg export HKLM\SYSTEM "%backup_file%" /y >nul 2>&1

:MENU
cls
echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║                     SYSTEM CONTROL TOOLKIT                     ║
echo ╠════════════════════════════════════════════════════════════════╣
echo ║ 1. Manage User Permissions                                     ║
echo ║ 2. List Open Ports                                             ║
echo ║ 3. Windows Defender Status                                     ║
echo ║ 4. Firewall Rules                                              ║
echo ║ 5. USB Connection History                                      ║
echo ║ 6. Active Sessions and Login Attempts                          ║
echo ║ 7. List Admin Group Members                                    ║
echo ║ 8. System Auto-Report (HTML)                                   ║
echo ║ 9. Services and Task Scan                                      ║
echo ║10. Event Log Analysis                                          ║
echo ║11. Advanced Malware Scan                                       ║
echo ║12. Network Security Analysis                                   ║
echo ║13. Hosts File Check                                            ║
echo ║14. Hidden File Hunter                                          ║
echo ║15. Scheduled Task Management                                   ║
echo ║16. Suspicious File Scan                                        ║
echo ║17. System Memory Analysis                                      ║
echo ║18. Connected Device Control                                    ║
echo ║19. Malicious Connection Analysis                               ║
echo ║20. Security Updates                                            ║
echo ║21. Password Policy                                             ║
echo ║22. Autostart Programs                                          ║
echo ║23. DNS Server Check                                            ║
echo ║24. Windows License Info                                        ║
echo ║25. Security Log Analysis                                       ║
echo ║26. User Account Control                                        ║
echo ║27. System Performance Monitor                                  ║
echo ║28. Firewall Management                                         ║
echo ║29. System Repair Tools                                         ║
echo ║30. Network Security Scan                                       ║
echo ║31. Disk Health Check                                           ║
echo ║32. Create System Restore Point                                 ║
echo ║33. Driver Updates                                              ║
echo ║34. System Resource Usage                                       ║
echo ║35. Network Speed Test                                          ║
echo ║36. Exit                                                        ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.
set /p choice=Enter your choice (1-36):

:: Current selections
if "%choice%"=="1" goto USER_PERMISSIONS
if "%choice%"=="2" goto PORT
if "%choice%"=="3" goto DEFENDER
if "%choice%"=="4" goto FIREWALL
if "%choice%"=="5" goto USB
if "%choice%"=="6" goto SESSION
if "%choice%"=="7" goto ADMIN
if "%choice%"=="8" goto REPORT
if "%choice%"=="9" goto SERVICES
if "%choice%"=="10" goto EVENTLOG
if "%choice%"=="11" goto MALWARE
if "%choice%"=="12" goto NETWORK_SECURITY
if "%choice%"=="13" goto HOSTS
if "%choice%"=="14" goto HIDDEN
if "%choice%"=="15" goto TASK_MANAGER
if "%choice%"=="16" goto SUSPICIOUS_FILES
if "%choice%"=="17" goto MEMORY_ANALYSIS
if "%choice%"=="18" goto CONNECTED_DEVICES
if "%choice%"=="19" goto MALICIOUS_CONNECTIONS
if "%choice%"=="20" goto UPDATE_CHECK
if "%choice%"=="21" goto PASSWORD_POLICY
if "%choice%"=="22" goto AUTO_START_PROGRAMS
if "%choice%"=="23" goto DNS_CHECK
if "%choice%"=="24" goto WINDOWS_KEY
if "%choice%"=="25" goto SECURITY_LOG
if "%choice%"=="26" goto USER_ACCOUNT_CHECK
if "%choice%"=="27" goto PERFORMANCE
if "%choice%"=="28" goto FIREWALL_MANAGER
if "%choice%"=="29" goto SYSTEM_REPAIR
if "%choice%"=="30" goto NETWORK_SECURITY
if "%choice%"=="31" goto DISK_HEALTH
if "%choice%"=="32" goto CREATE_RESTORE
if "%choice%"=="33" goto DRIVER_UPDATE
if "%choice%"=="34" goto RESOURCE_MONITOR
if "%choice%"=="35" goto SPEED_TEST
if "%choice%"=="36" exit

:: Invalid input check
echo Invalid selection! Please enter a number between 1-36.
timeout /t 2 >nul
goto MENU

:USER_PERMISSIONS
cls
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                   Manage User Permissions                     ║
echo ╠══════════════════════════════════════════════════════════════╣
echo ║ 1. Add User to Administrators                                ║
echo ║ 2. Remove User from Administrators                           ║
echo ║ 3. Back to Main Menu                                         ║
echo ╚══════════════════════════════════════════════════════════════╝
set /p perm_choice=Enter your choice (1-3): 
if "%perm_choice%"=="1" goto ADMIN_ADD
if "%perm_choice%"=="2" goto ADMIN_REMOVE
if "%perm_choice%"=="3" goto MENU
goto USER_PERMISSIONS

:ADMIN_ADD
cls
set /p username=Enter the username to be added to admin group: 
net localgroup Administrators %username% /add
echo %username% has been added to the admin group.
pause
goto MENU

:ADMIN_REMOVE
cls
set /p username=Enter the username to be removed from admin group: 
net localgroup Administrators %username% /delete
echo %username% has been removed from the admin group.
pause
goto MENU

:PORT
cls
echo.
echo Open Ports:
echo ---------------------------------
netstat -an | findstr "LISTEN"
echo ---------------------------------
pause
goto MENU

:DEFENDER
cls
echo.
echo Windows Defender Status:
echo ----------------------------
powershell Get-MpComputerStatus
echo ----------------------------
pause
goto MENU

:FIREWALL
cls
echo.
echo Firewall Rules:
echo ------------------------------
netsh advfirewall firewall show rule name=all
echo ------------------------------
pause
goto MENU

:USB
cls
echo.
echo USB Connection History:
echo -------------------------
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
echo -------------------------
pause
goto MENU

:SESSION
cls
echo.
echo Active Sessions and Login Attempts:
echo ---------------------------------------
query user
echo ---------------------------------------
pause
goto MENU

:ADMIN
cls
echo.
echo Admin Group Members:
echo -------------------------
net localgroup Administrators
echo -------------------------
pause
goto MENU

:REPORT
cls
echo.
echo Creating System Auto-Report (report.txt)...
echo -----------------------------
echo System Information >> report.txt
systeminfo >> report.txt
echo -----------------------------
echo Ports >> report.txt
netstat -an >> report.txt
echo -----------------------------
echo Windows Defender >> report.txt
powershell Get-MpComputerStatus >> report.txt
echo -----------------------------
echo Firewall >> report.txt
netsh advfirewall firewall show rule name=all >> report.txt
echo -----------------------------
pause
goto MENU

:SERVICES
cls
echo.
echo System Services:
echo ---------------------------
sc query
echo ---------------------------
pause
goto MENU

:EVENTLOG
cls
echo.
echo Event Log Analysis:
echo ------------------------
wevtutil qe System /f:text
echo ------------------------
pause
goto MENU

:MALWARE
cls
echo.
echo Malware and Autorun Detection:
echo ---------------------------
dir C:\ /a:h /s /b
echo ---------------------------
pause
goto MENU

:NETWORK_SECURITY
cls
echo Network Security Analysis
echo -------------------
:: Port scan
echo [*] Checking critical ports...
for %%p in (21,22,23,25,53,80,443,445,3389,5900) do (
    powershell -Command "Test-NetConnection -ComputerName localhost -Port %%p" | findstr "TcpTestSucceeded"
)
:: DNS cache
echo [*] Checking DNS Cache...
ipconfig /displaydns | findstr "Record Name"
:: Active connections
echo [*] Checking suspicious connections...
netstat -nao | findstr "ESTABLISHED"
pause
goto MENU

:HOSTS
cls
echo.
echo Hosts File Manipulation:
echo ------------------------------
type C:\Windows\System32\drivers\etc\hosts
echo ------------------------------
pause
goto MENU

:HIDDEN
cls
echo.
echo Hidden File Hunter:
echo ---------------------
dir C:\ /a /s
echo ---------------------
pause
goto MENU

:TASK_MANAGER
cls
echo Scheduled Task Management
echo --------------------------
echo 1. List Tasks
echo 2. Create New Task
echo 3. Delete Task
echo 4. Back to Main Menu
set /p task_choice=Enter your choice: 
if "%task_choice%"=="1" schtasks /query /fo list
if "%task_choice%"=="2" call :CREATE_TASK
if "%task_choice%"=="3" call :DELETE_TASK
if "%task_choice%"=="4" goto MENU
pause
goto TASK_MANAGER

:SUSPICIOUS_FILES
cls
echo Scanning for Suspicious Files:
echo ----------------------------
dir C:\ /a /s | findstr /i ".exe .dll .scr"
echo ----------------------------
pause
goto MENU

:MEMORY_ANALYSIS
cls
echo Memory Analysis:
echo ------------------
tasklist /fi "status eq running"
echo ------------------
pause
goto MENU

:CONNECTED_DEVICES
cls
echo Connected Devices on Network:
echo -----------------------------
arp -a
echo -----------------------------
pause
goto MENU

:MALICIOUS_CONNECTIONS
cls
echo Malicious Connections:
echo ---------------------------
netstat -an | findstr "ESTABLISHED"
echo ---------------------------
pause
goto MENU

:UPDATE_CHECK
cls
echo Security Updates Check:
echo -------------------------------
wmic qfe list brief /format:table
echo -------------------------------
pause
goto MENU

:PASSWORD_POLICY
cls
echo Password Policy Analysis:
echo -------------------------
net accounts
echo -------------------------
pause
goto MENU

:AUTO_START_PROGRAMS
cls
echo Autostart Programs:
echo ------------------------------
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
echo ------------------------------
pause
goto MENU

:DNS_CHECK
cls
echo DNS Server Settings:
echo ----------------------
ipconfig /all | findstr "DNS"
echo ----------------------
pause
goto MENU

:SECURITY_LOG
cls
echo Security Log Analysis:
echo -----------------------
wevtutil qe Security /f:text
echo -----------------------
pause
goto MENU

:USER_ACCOUNT_CHECK
cls
echo User Accounts:
echo ----------------------
net user
echo ----------------------
pause
goto MENU

:WINDOWS_KEY
cls
echo.
echo ================================
echo  Windows License Info Tool
echo ================================
echo.

setlocal enabledelayedexpansion


set "output=%TEMP%\output.txt"
set "vbs_script=%TEMP%\temp_win_key.vbs"


if exist "%output%" del /f /q "%output%"
if exist "%vbs_script%" del /f /q "%vbs_script%"


echo [*] Retrieving license key using PowerShell...
set "product_key="
for /f "tokens=*" %%i in ('powershell -Command "try { (Get-WmiObject -Query 'Select * from SoftwareLicensingService').OA3xOriginalProductKey } catch { '' }"') do (
    set "product_key=%%i"
)


if defined product_key (
    echo [✓] PowerShell Product Key: !product_key!
) else (
    echo [!] Unable to retrieve product key using PowerShell. The system may be activated with a digital license.
)


echo.
echo [*] Checking for backup product key using VBS...
(
echo Set WshShell = CreateObject("WScript.Shell")
echo key = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\BackupProductKeyDefault"
echo On Error Resume Next
echo WScript.Echo WshShell.RegRead(key)
) > "%vbs_script%"

cscript //nologo "%vbs_script%" > "%output%"
del "%vbs_script%"


set "backup_key="
for /f "tokens=*" %%j in (%output%) do (
    set "backup_key=%%j"
)

if defined backup_key (
    echo [✓] Backup Product Key (Registry): !backup_key!
) else (
    echo [!] Backup product key not found or access denied.
)


del "%output%" >nul 2>&1

echo.
echo -----------------------------------------------
echo [✓] License information retrieval completed.
pause
goto MENU

:MALWARE
cls
echo Performing Advanced Malware Scan...
echo ----------------------------------------
:: Check critical system folders
dir /s /b "C:\Windows\System32\*.exe" > "%TEMP%\system_files.txt"
:: Scan for suspicious file extensions
dir /s /b "C:\*.tmp" "C:\*.dat" "C:\*.exe" | findstr /i "temp appdata" > "%TEMP%\suspicious.txt"
:: List newly added executable files
forfiles /P "C:\Windows" /M *.exe /D +0 /C "cmd /c echo @path @fdate"
echo ----------------------------------------
type "%TEMP%\suspicious.txt"
del "%TEMP%\system_files.txt" "%TEMP%\suspicious.txt"
pause
goto MENU

:REPORT
cls
echo Generating Detailed System Report...
set "report_file=%USERPROFILE%\Desktop\system_report_%date:~-4,4%%date:~-7,2%%date:~-10,2%.html"
echo ^<!DOCTYPE html^> > "%report_file%"
echo ^<html^>^<head^>^<title^>System Report^</title^>^</head^>^<body^> >> "%report_file%"
echo ^<h2^>System Information^</h2^> >> "%report_file%"
systeminfo | powershell -Command "$input | ConvertTo-Html" >> "%report_file%"
echo ^<h2^>Security Status^</h2^> >> "%report_file%"
powershell "Get-MpComputerStatus | ConvertTo-Html" >> "%report_file%"
echo ^<h2^>Installed Programs^</h2^> >> "%report_file%"
wmic product get name,version | powershell -Command "$input | ConvertTo-Html" >> "%report_file%"
echo ^</body^>^</html^> >> "%report_file%"
echo Report generated: %report_file%
pause
goto MENU

:NETWORK_SECURITY
cls
echo Network Security Analysis
echo -------------------

echo [*] Checking critical ports...
for %%p in (21,22,23,25,53,80,443,445,3389,5900) do (
    powershell -Command "Test-NetConnection -ComputerName localhost -Port %%p" | findstr "TcpTestSucceeded"
)

echo [*] Checking DNS Cache...
ipconfig /displaydns | findstr "Record Name"

echo [*] Checking suspicious connections...
netstat -nao | findstr "ESTABLISHED"
pause
goto MENU

:PERFORMANCE
cls
echo System Performance Analysis
echo ------------------------
:: CPU Usage
echo [*] CPU Usage:
powershell -Command "Get-WmiObject Win32_Processor | Select-Object LoadPercentage,Name | Format-Table -AutoSize"

:: RAM Usage
echo [*] RAM Usage:
powershell -Command "$os = Get-WmiObject Win32_OperatingSystem; $total = [math]::Round($os.TotalVisibleMemorySize/1MB, 2); $free = [math]::Round($os.FreePhysicalMemory/1MB, 2); $used = $total - $free; Write-Host ('Total RAM: {0:N2} GB' -f $total); Write-Host ('Used RAM: {0:N2} GB' -f $used); Write-Host ('Free RAM: {0:N2} GB' -f $free); Write-Host ('Usage Rate: {0:N2}%' -f (($used/$total)*100))"

:: Disk Usage
echo [*] Disk Usage:
powershell -Command "Get-WmiObject Win32_LogicalDisk | ForEach-Object {Write-Host ('Drive: {0}' -f $_.DeviceID); Write-Host ('Total Space: {0:N2} GB' -f ($_.Size/1GB)); Write-Host ('Free Space: {0:N2} GB' -f ($_.FreeSpace/1GB)); Write-Host ('Usage Rate: {0:N2}%' -f ((($_.Size-$_.FreeSpace)/$_.Size)*100)); Write-Host '------------------------'}"

pause
goto MENU

:FIREWALL_MANAGER
cls
echo Firewall Management
echo ------------------------
echo 1. Enable Firewall
echo 2. Disable Firewall
echo 3. Add Rule
echo 4. List Rules
echo 5. Back to Main Menu
set /p fw_choice=Enter your choice: 
if "%fw_choice%"=="1" netsh advfirewall set allprofiles state on
if "%fw_choice%"=="2" netsh advfirewall set allprofiles state off
if "%fw_choice%"=="3" call :ADD_FIREWALL_RULE
if "%fw_choice%"=="4" netsh advfirewall firewall show rule name=all
if "%fw_choice%"=="5" goto MENU
pause
goto FIREWALL_MANAGER

:SYSTEM_REPAIR
cls
echo System Repair Tools
echo ---------------------
echo [*] Checking system files...
sfc /scannow
echo [*] Repairing Windows image...
DISM /Online /Cleanup-Image /RestoreHealth
echo [*] Checking disk errors...
chkdsk C: /f /r
pause
goto MENU

:TASK_MANAGER
cls
echo Scheduled Task Management
echo --------------------------
echo 1. List Tasks
echo 2. Create New Task
echo 3. Delete Task
echo 4. Back to Main Menu
set /p task_choice=Enter your choice: 
if "%task_choice%"=="1" schtasks /query /fo list
if "%task_choice%"=="2" call :CREATE_TASK
if "%task_choice%"=="3" call :DELETE_TASK
if "%task_choice%"=="4" goto MENU
pause
goto TASK_MANAGER

:ERROR_LOGGING
:: Advanced error logging
set "log_file=%~dp0\logs\error_log.txt"
if not exist "%~dp0\logs" mkdir "%~dp0\logs"
echo %date% %time% - Error Code: %errorlevel% >> "%log_file%"
echo Command: %cmdcmdline% >> "%log_file%"
echo System: %computername% >> "%log_file%"
echo User: %username% >> "%log_file%"
echo ---------------------------------------- >> "%log_file%"
