@echo off
set local_dir=D:\ruiyun\MyPaper\zhangscheme
set remote_dir=/root/zhangscheme/
::账号
set account=root
set password=RuiYun123456
set host=zzj.red
set port=22

pscp -r -v -pw RuiYun123456 -P 22 %local_dir% root@zzj.red:/root/
REM putty.exe -ssh root@zzj.red:22 -pw RuiYun123456 -m %local_dir%\upload.bat.sh
REM pscp -r -v -pw RuiYun123456 -P 22 root@zzj.red:%remote_dir%upload.bat.log %local_dir%\upload.bat.log