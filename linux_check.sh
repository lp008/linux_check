#!/bin/bash
echo "

	
                         ____ _  _ ____ ____ ____ ____ _  _ ____ _   _ 
                           |___ |\/| |___ |__/ | __ |___ |\ | |     \_/  
                           |___ |  | |___ |  \ |__] |___ | \| |___   |  

                                        Powered by Vampire 
                                        Version 1.1                                           

"
# 验证是否为root权限
echo -e "\033[34m[-]环境检测：\033[0m"
if [ $UID -ne 0 ]; then
    echo -e "\033[34m[!]请使用root权限运行!\033[0m"
    exit 1
else
    echo "当前为root权限"
    printf "\n"
fi

echo -e "\033[34m[-]主机信息：\033[0m"
# 当前用户
echo -e "USER:\t\t" $(whoami) 2>/dev/null
# 主机名
echo -e "Hostname: \t" $(hostname -s)
# uptime
echo -e "uptime: \t" $(uptime | awk -F ',' '{print $1}')
printf "\n"

# CPU占用率
echo -e "\033[34m[-]CPU使用率：\033[0m"
awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null | while read line; do
	echo "$line" | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
        print$1" Free "free/total*100"%",\
        "Used " (total-free)/total*100"%"}'
done
printf "\n"

# CPU占用TOP 15
cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -15) 2>/dev/null
echo -e "\033[34m[-]CPU TOP 15：\033[0m\n${cpu}\n"

# 内存占用
echo -e "\033[34m[-]内存占用：\033[0m"
free -m
printf "\n"

# 内存占用TOP 15
cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -15) 2>/dev/null
echo -e "\033[34m[-]内存占用 TOP 15：\033[0m\n${cpu}\n"

# 查看passwd下的用户，是否存在可疑用户
echo -e "\033[34m[-]/etc/passwd:\033[0m"
cat /etc/passwd |grep -nvi "nologin"

# 显示可远程登录的用户
echo -e "\033[34m[-]可远程登录用户：\033[0m"
awk -F: '/\$1|\$6/{print $1}' /etc/shadow

# 查看有无特权用户，并将其删除
echo -e "\033[34m[-]特权用户：\033[0m"
admin=`awk -F: '$3==0{print $1}' /etc/passwd`
echo -e "$admin"
printf "\n"

# 显示处于连接状态的端口号和响应的进程
port=`netstat -antup`
echo -e "\033[34m[-]netstat端口连接状态:：\033[0m"
echo -e "$port"
printf "\n"

# 显示IP地址信息
echo -e "\033[34m[-]IP地址信息:\033[0m"
ifconfig
printf "\n"

# 显示路由表信息
echo -e "\033[34m[-]路由表信息:\033[0m" | tee -a $filename
/sbin/route -nee | tee -a $filename
echo -e "\n" | tee -a $filename

# 显示路由转发信息
echo -e "\033[34m[-]路由转发信息:\033[0m" | tee -a $filename
ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}')
if [ -n "$ip_forward" ]; then
    echo "/proc/sys/net/ipv4/ip_forward 已开启路由转发" | tee -a $filename
else
    echo "该服务器未开启路由转发" | tee -a $filename
fi
echo -e "\n" | tee -a $filename

# 显示DNS配置信息
echo -e "\033[34m[-]DNS配置信息:\033[0m" | tee -a $filename
cat /etc/resolv.conf | tee -a $filename
echo -e "\n" | tee -a $filename

# 显示ARP信息
echo -e "\033[34m[-]ARP配置信息:\033[0m" | tee -a $filename
arp -n -a | tee -a $filename
echo -e "\n" | tee -a $filename

# 显示IPTABLES防火墙信息
echo -e "\033[34m[-]IPTABLES防火墙信息:\033[0m" | tee -a $filename
iptables -L | tee -a $filename
echo -e "\n" | tee -a $filename

# 查看历史命令，并显示异常操作
shell=`cat ~/.bash_history | grep -e "chmod" -e "rm" -e "wget" -e "ssh" -e "tar" -e "zip" -e "scp" -e "curl" -e "reboot" -e "init" -e "shutdown" -e "chattr" -e "crontab" -e "iptables" -e "\./"`
echo -e "\033[34m[-]历史高危命令:：\033[0m"
echo -e "$shell"
printf "\n"

# 用户自定义启动项
echo -e "\033[34m[-]用户自定义启动项：\033[0m"
chkconfig=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}')
if [ -n "$chkconfig" ];then
	(echo "[*]用户自定义启动项:" && echo "$chkconfig")
else
	echo "[!]未发现用户自定义启动项"
fi
printf "\n"

# 可能存在的危险启动项
echo -e "\033[34m[-]危险启动项：\033[0m"
#dangerstarup=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}' | grep -E "\.(sh|per|py)$")
dangerstarup=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}' | grep -E "\.(sh|per|py)")
if [ -n "$dangerstarup" ];then
	echo "[!]发现危险启动项:" && echo "$dangerstarup"
else
	echo "[*]未发现危险启动项"
fi
printf "\n"

# 系统定时任务
echo -e "\033[34m[-]系统定时任务：\033[0m"
syscrontab=$(more /etc/crontab | grep -v "# run-parts" | grep run-parts)
if [ -n "$syscrontab" ];then
	echo "[!]发现存在系统定时任务:" && more /etc/crontab 
else
	echo "[*]未发现系统定时任务"
fi
printf "\n"

# 可疑定时任务
echo -e "\033[34m[-]可疑定时任务：\033[0m"
#dangersyscron=$(egrep "((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)$))"  /etc/cron*/* /var/spool/cron/*)
dangersyscron=$(egrep "((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)))"  /etc/cron*/* /var/spool/cron/*)
if [ -n "$dangersyscron" ];then
	(echo "[!]发现可疑定时任务：" && echo "$dangersyscron")
else
	echo "[*]未发现可疑系统定时任务"
fi
printf "\n"

# 查看日志配置
echo -e "\033[34m[-]日志配置：\033[0m"
logconf=$(more /etc/rsyslog.conf | egrep -v "#|^$")
if [ -n "$logconf" ];then
	(echo "[*]日志配置如下:" && echo "$logconf")
else
	echo "[!]未发现日志配置文件"
fi
printf "\n"

# 检查日志是否被清除
echo -e "\033[34m[-]查看日志是否被清除：\033[0m"
logs=$(ls -l /var/log/)
if [ -n "$logs" ];then
	echo "[*]日志文件存在"
else
	echo "[!]日志文件不存在,可能被清除！"
fi
printf "\n"

# secure日志分析
echo -e "\033[34m[-]secure日志分析-登录成功情况：\033[0m"
loginsuccess=$(more /var/log/secure* | grep "Accepted" | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginsuccess" ];then
	(echo "[*]日志中分析到以下用户成功登录:" && echo "$loginsuccess") 
	(echo "[*]登录成功的IP及次数如下：" && grep "Accepted " /var/log/secure* | awk '{print $11}' | sort -nr | uniq -c ) 
	(echo "[*]登录成功的用户及次数如下:" && grep "Accepted" /var/log/secure* | awk '{print $9}' | sort -nr | uniq -c ) 
else
	echo "[*]日志中未发现成功登录的情况"
fi
printf "\n"

echo -e "\033[34m[-]secure日志分析-登录失败情况：\033[0m"
loginfailed=$(more /var/log/secure* | grep "Failed" | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginfailed" ];then
	(echo "[!]日志中发现以下登录失败的情况:" && echo "$loginfailed") |  tee -a $danger_file 
	(echo "[!]登录失败的IP及次数如下:" && grep "Failed" /var/log/secure* | awk '{print $11}' | sort -nr | uniq -c) 
	(echo "[!]登录失败的用户及次数如下:" && grep "Failed" /var/log/secure* | awk '{print $9}' | sort -nr | uniq -c) 
else
	echo "[*]日志中未发现登录失败的情况"
fi
printf "\n"

echo -e "\033[34m[-]secure日志分析-本机登录情况：\033[0m"
systemlogin=$(more /var/log/secure* | grep -E "sshd:session.*session opened" | awk '{print $1,$2,$3,$11}')
if [ -n "$systemlogin" ];then
	(echo "[*]本机登录情况:" && echo "$systemlogin")
	(echo "[*]本机登录账号及次数如下:" && more /var/log/secure* | grep -E "sshd:session.*session opened" | awk '{print $11}' | sort -nr | uniq -c)
else
	echo "[!]未发现在本机登录退出情况！"
fi
printf "\n"

echo -e "\033[34m[-]secure日志分析-新增用户情况：\033[0m"
newusers=$(more /var/log/secure* | grep "new user"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
if [ -n "$newusers" ];then
	(echo "[!]日志中发现新增用户:" && echo "$newusers")
	(echo "[*]新增用户账号及次数如下:" && more /var/log/secure* | grep "new user" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c)
else
	echo "[*]日志中未发现新增加用户"
fi
printf "\n"

# message日志分析
echo -e "\033[34m[-]message日志分析-文件传输情况：\033[0m"
zmodem=$(more /var/log/message* | grep "ZMODEM:.*BPS")
if [ -n "$zmodem" ];then
	(echo "[!]传输文件情况:" && echo "$zmodem")
else
	echo "[*]日志中未发现传输文件"
fi
printf "\n"

echo -e "\033[34m[-]cron日志分析-定时下载：\033[0m"
cron_download=$(more /var/log/cron* | grep -E "wget|curl|.systemd")
if [ -n "$cron_download" ];then
        (echo "[!]定时下载情况:" && echo "$cron_download")
else
        echo "[*]未发现定时下载情况"
fi
printf "\n"

echo -e "\033[34m[-]cron日志分析-定时执行脚本：\033[0m"
cron_shell=$(more /var/log/cron* | grep -E "\.py|\.sh|\.pl") 
if [ -n "$cron_shell" ];then
	(echo "[!]发现定时执行脚本:" && echo "$cron_shell")
else
	echo "[*]未发现定时下载脚本"
fi
printf "\n"

# btmp日志分析
echo -e "\033[34m[-]btmp日志分析-错误登录日志分析：\033[0m"
lastb=$(lastb)
if [ -n "$lastb" ];then
	(echo "[！]错误登录日志如下:" && echo "$lastb")
else
	echo "[*]未发现错误登录日志"
fi
printf "\n"

# lastlog日志分析
echo -e "\033[34m[-]lastlog日志分析-最后一次登录：\033[0m"
lastlog=$(lastlog)
if [ -n "$lastlog" ];then
	(echo "[！]所有用户最后一次登录日志如下:" && echo "$lastlog")
else
	echo "[*]未发现所有用户最后一次登录日志"
fi
printf "\n"

# wtmp日志分析
echo -e "\033[34m[-]wtmp日志分析-用户登录分析：\033[0m"
lasts=$(last | grep pts | grep -vw :0)
if [ -n "$lasts" ];then
	(echo "[！]历史上登录到本机的用户如下:" && echo "$lasts")
else
	echo "[*]未发现历史上登录到本机的用户信息"
fi
printf "\n"

# 敏感目录文件
echo -e "\033[34m[-]敏感文件列表：\033[0m"
find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*backdoor|.*tunnel\.(php|jsp|asp|py)|.*\bnc|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc'
echo -e "\033[34m[-]各tmp目录文件：\033[0m"
ls /tmp /tmp/.X11-unix/ /var/tmp /dev/shm -alht | tee -a $filename
echo -e "\n" | tee -a $filename

# SSH KEY敏感信息
echo -e "\033[34m[-]SSH key信息：\033[0m" | tee -a $filename
sshkey=${HOME}/.ssh/authorized_keys
if [ -e "${sshkey}" ]; then
    cat ${sshkey} | tee -a $filename
else
    echo -e "[*]SSH key文件不存在\n" | tee -a $filename
fi
echo -e "\n" | tee -a $filename

# 显示Rootkit内核模块信息
echo -e "\033[34m[-]Rootkit内核模块信息：\033[0m" | tee -a $filename
kernel=$(cat /proc/kallsyms | egrep 'hide_tcp4_port|hidden_files|hide_tcp6_port')
if [ -n "$kernel" ]; then
	echo "[!]存在内核敏感函数！ 疑似Rootkit内核模块" | tee -a $filename
else
	echo "[*]未找到内核敏感函数" | tee -a $filename
fi
echo -e "\n" | tee -a $filename

# netstat-恶意挖矿进程
echo -e "\033[34m[-]netstat查找恶意挖矿进程：\033[0m"
declare -A netlist
netlist=([a1]=`netstat -anp | grep 185.71.65.238 | awk '{print}'` [a2]=`netstat -anp | grep 140.82.52.87 | awk '{print}'` [a3]=`netstat -antp | grep '46.243.253.15' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print}'` [a4]=`netstat -antp | grep '176.31.6.16' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print}'` [a5]=`netstat -anp | grep :443 | awk '{print}'` [a6]=`netstat -anp | grep :23 | awk '{print}'` [a7]=`netstat -anp | grep :143 | awk '{print}'` [a8]=`netstat -anp | grep :8080 | awk '{print}'` [a9]=`netstat -anp | grep :2222 | awk '{print}'` [a10]=`netstat -anp | grep :3333 | awk '{print}'` [a11]=`netstat -anp | grep :3389 | awk '{print}'` [a12]=`netstat -anp | grep :4444 | awk '{print}'` [a13]=`netstat -anp | grep :5555 | awk '{print}'` [a14]=`netstat -anp | grep :6666 | awk '{print}'` [a15]=`netstat -anp | grep :6665 | awk '{print}'` [a16]=`netstat -anp | grep :6667 | awk '{print}'` [a17]=`netstat -anp | grep :7777 | awk '{print}'` [a18]=`netstat -anp | grep :8444 | awk '{print}'` [a19]=`netstat -anp | grep :3347 | awk '{print}'` [a20]=`netstat -anp | grep :14433 | awk '{print}'`)
for a in $(echo ${!netlist[*]});
do
        #echo "$a result is ${netlist[$a]}";
        if [ -n "${netlist[$a]}" ];then
                (echo "[!]发现恶意挖矿进程:" && echo "${netlist[$a]}")
        else
                #echo "[*]未发现恶意挖矿进程"
                for ((i=1;i<=100;i++));
                do
                        let b+=$i
                done
        fi
done
if [ "$b" -ge 0 ];then
        echo "[*]未发现恶意挖矿进程"
else
        echo ""
fi
printf "\n"

# ps-恶意挖矿进程
echo -e "\033[34m[-]ps查找恶意挖矿进程：\033[0m"
declare -A pslist
pslist=([p1]=`ps aux | grep -v grep | grep ':3333' | awk '{print}' | xargs -I % echo %` [p2]=`ps aux | grep -v grep | grep ':5555' | awk '{print}' | xargs -I % echo %` [p3]=`ps aux | grep -v grep | grep 'kworker -c\\' | awk '{print}' | xargs -I % echo %` [p4]=`ps aux | grep -v grep | grep 'log_' | awk '{print}' | xargs -I % echo %` [p5]=`ps aux | grep -v grep | grep 'systemten' | awk '{print}' | xargs -I % echo %` [p6]=`ps aux | grep -v grep | grep 'voltuned' | awk '{print}' | xargs -I % echo %` [p7]=`ps aux | grep -v grep | grep 'darwin' | awk '{print}' | xargs -I % echo %` [p8]=`ps aux | grep -v grep | grep '/tmp/dl' | awk '{print}' | xargs -I % echo %` [p9]=`ps aux | grep -v grep | grep '/tmp/ddg' | awk '{print}' | xargs -I % echo %` [p10]=`ps aux | grep -v grep | grep '/tmp/pprt' | awk '{print}' | xargs -I % echo %` [p11]=`ps aux | grep -v grep | grep '/tmp/ppol' | awk '{print}' | xargs -I % echo %` [p12]=`ps aux | grep -v grep | grep '/tmp/65ccE*' | awk '{print}' | xargs -I % echo %` [p13]=`ps aux | grep -v grep | grep '/tmp/jmx*' | awk '{print}' | xargs -I % echo %` [p14]=`ps aux | grep -v grep | grep '/tmp/2Ne80*' | awk '{print}' | xargs -I % echo %` [p15]=`ps aux | grep -v grep | grep 'IOFoqIgyC0zmf2UR' | awk '{print}' | xargs -I % echo %` [p16]=`ps aux | grep -v grep | grep '45.76.122.92' | awk '{print}' | xargs -I % echo %` [p17]=`ps aux | grep -v grep | grep '51.38.191.178' | awk '{print}' | xargs -I % echo %` [p18]=`ps aux | grep -v grep | grep '51.15.56.161' | awk '{print}' | xargs -I % echo  %` [p19]=`ps aux | grep -v grep | grep '86s.jpg' | awk '{print}' | xargs -I % echo %` [p20]=`ps aux | grep -v grep | grep 'aGTSGJJp' | awk '{print}' | xargs -I % echo %` [p21]=`ps aux | grep -v grep | grep 'nMrfmnRa' | awk '{print}' | xargs -I % echo %` [p22]=`ps aux | grep -v grep | grep 'PuNY5tm2' | awk '{print}' | xargs -I % echo  %` [p23]=`ps aux | grep -v grep | grep 'I0r8Jyyt' | awk '{print}' | xargs -I % echo  %` [p24]=`ps aux | grep -v grep | grep 'AgdgACUD' | awk '{print}' | xargs -I % echo  %` [p25]=`ps aux | grep -v grep | grep 'uiZvwxG8' | awk '{print}' | xargs -I % echo  %` [p26]=`ps aux | grep -v grep | grep 'hahwNEdB' | awk '{print}' | xargs -I % echo  %` [p27]=`ps aux | grep -v grep | grep 'BtwXn5qH' | awk '{print}' | xargs -I % echo  %` [p28]=`ps aux | grep -v grep | grep '3XEzey2T' | awk '{print}' | xargs -I % echo  %` [p29]=`ps aux | grep -v grep | grep 't2tKrCSZ' | awk '{print}' | xargs -I % echo  %` [p30]=`ps aux | grep -v grep | grep 'HD7fcBgg' | awk '{print}' | xargs -I % echo  %` [p31]=`ps aux | grep -v grep | grep 'zXcDajSs' | awk '{print}' | xargs -I % echo  %` [p32]=`ps aux | grep -v grep | grep '3lmigMo' | awk '{print}' | xargs -I % echo  %` [p33]=`ps aux | grep -v grep | grep 'AkMK4A2' | awk '{print}' | xargs -I % echo  %` [p34]=`ps aux | grep -v grep | grep 'AJ2AkKe' | awk '{print}' | xargs -I % echo  %` [p35]=`ps aux | grep -v grep | grep 'HiPxCJRS' | awk '{print}' | xargs -I % echo  %` [p36]=`ps aux | grep -v grep | grep 'http_0xCC030' | awk '{print}' | xargs -I % echo  %` [p37]=`ps aux | grep -v grep | grep 'http_0xCC031' | awk '{print}' | xargs -I % echo  %` [p38]=`ps aux | grep -v grep | grep 'http_0xCC032' | awk '{print}' | xargs -I % echo  %` [p39]=`ps aux | grep -v grep | grep 'http_0xCC033' | awk '{print}' | xargs -I % echo  %` [p40]=`ps aux | grep -v grep | grep "C4iLM4L" | awk '{print}' | xargs -I % echo  %` [p41]=`ps aux | grep -v grep | grep 'aziplcr72qjhzvin' | awk '{print}' | xargs -I % echo  %` [p42]=`ps aux | grep -v grep | awk '{ if(substr($11,1,2)=="./" && substr($12,1,2)=="./") print $2 }' | xargs -I % echo  %` [p43]=`ps aux | grep -v grep | grep '/boot/vmlinuz' | awk '{print}' | xargs -I % echo  %` [p44]=`ps aux | grep -v grep | grep "i4b503a52cc5" | awk '{print}' | xargs -I % echo  %` [p45]=`ps aux | grep -v grep | grep "dgqtrcst23rtdi3ldqk322j2" | awk '{print}' | xargs -I % echo  %` [p46]=`ps aux | grep -v grep | grep "2g0uv7npuhrlatd" | awk '{print}' | xargs -I % echo  %` [p47]=`ps aux | grep -v grep | grep "nqscheduler" | awk '{print}' | xargs -I % echo  %` [p48]=`ps aux | grep -v grep | grep "rkebbwgqpl4npmm" | awk '{print}' | xargs -I % echo  %` [p49]=`ps aux | grep -v grep | grep -v aux | grep "]" | awk '$3>10.0{print}' | xargs -I % echo  %` [p50]=`ps aux | grep -v grep | grep "2fhtu70teuhtoh78jc5s" | awk '{print}' | xargs -I % echo  %` [p51]=`ps aux | grep -v grep | grep "0kwti6ut420t" | awk '{print}' | xargs -I % echo  %` [p52]=`ps aux | grep -v grep | grep "44ct7udt0patws3agkdfqnjm" | awk '{print}' | xargs -I % echo  %` [p53]=`ps aux | grep -v grep | grep -v "/" | grep -v "-" | grep -v "_" | awk 'length($11)>19{print}' | xargs -I % echo  %` [p54]=`ps aux | grep -v grep | grep "\[^" | awk '{print}' | xargs -I % echo  %` [p55]=`ps aux | grep -v grep | grep "rsync" | awk '{print}' | xargs -I % echo  %` [p56]=`ps aux | grep -v grep | grep "watchd0g" | awk '{print}' | xargs -I % echo  %` [p57]=`ps aux | grep -v grep | egrep 'wnTKYg|2t3ik|qW3xT.2|ddg' | awk '{print}' | xargs -I % echo  %` [p58]=`ps aux | grep -v grep | grep "158.69.133.18:8220" | awk '{print}' | xargs -I % echo  %` [p59]=`ps aux | grep -v grep | grep "/tmp/java" | awk '{print}' | xargs -I % echo  %` [p60]=`ps aux | grep -v grep | grep 'gitee.com' | awk '{print}' | xargs -I % echo  %` [p61]=`ps aux | grep -v grep | grep '/tmp/java' | awk '{print}' | xargs -I % echo  %` [p62]=`ps aux | grep -v grep | grep '104.248.4.162' | awk '{print}' | xargs -I % echo  %` [p63]=`ps aux | grep -v grep | grep '89.35.39.78' | awk '{print}' | xargs -I % echo  %` [p64]=`ps aux | grep -v grep | grep '/dev/shm/z3.sh' | awk '{print}' | xargs -I % echo  %` [p65]=`ps aux | grep -v grep | grep 'kthrotlds' | awk '{print}' | xargs -I % echo  %` [p66]=`ps aux | grep -v grep | grep 'ksoftirqds' | awk '{print}' | xargs -I % echo  %` [p67]=`ps aux | grep -v grep | grep 'netdns' | awk '{print}' | xargs -I % echo  %` [p68]=`ps aux | grep -v grep | grep 'watchdogs' | awk '{print}' | xargs -I % echo  %` [p69]=`ps aux | grep -v grep | grep 'kdevtmpfsi' | awk '{print}' | xargs -I % echo  %` [p70]=`ps aux | grep -v grep | grep 'kinsing' | awk '{print}' | xargs -I % echo  %` [p71]=`ps aux | grep -v grep | grep 'redis2' | awk '{print}' | xargs -I % echo  %` [p72]=`ps aux | grep -v grep | grep -v root | grep -v dblaunch | grep -v dblaunchs | grep -v dblaunched | grep -v apache2 | grep -v atd | grep -v kdevtmpfsi | awk '$3>80.0{print}' | xargs -I % echo  %` [p73]=`ps aux | grep -v grep | grep -v aux | grep " ps" | awk '{print}' | xargs -I % echo  %` [p74]=`ps aux | grep -v grep | grep "sync_supers" | cut -c 9-15 | xargs -I % echo  %` [p75]=`ps aux | grep -v grep | grep "cpuset" | cut -c 9-15 | xargs -I % echo  %` [p76]=`ps aux | grep -v grep | grep -v aux | grep "x]" | awk '{print}' | xargs -I % echo  %` [p77]=`ps aux | grep -v grep | grep -v aux | grep "sh] <" | awk '{print}' | xargs -I % echo  %` [p78]=`ps aux | grep -v grep | grep -v aux | grep " \[]" | awk '{print}' | xargs -I % echo  %` [p79]=`ps aux | grep -v grep | grep '/tmp/l.sh' | awk '{print}' | xargs -I % echo  %` [p80]=`ps aux | grep -v grep | grep '/tmp/zmcat' | awk '{print}' | xargs -I % echo  %` [p81]=`ps aux | grep -v grep | grep 'hahwNEdB' | awk '{print}' | xargs -I % echo  %` [p82]=`ps aux | grep -v grep | grep 'CnzFVPLF' | awk '{print}' | xargs -I % echo  %` [p83]=`ps aux | grep -v grep | grep 'CvKzzZLs' | awk '{print}' | xargs -I % echo  %` [p84]=`ps aux | grep -v grep | grep 'aziplcr72qjhzvin' | awk '{print}' | xargs -I % echo  %` [p85]=`ps aux | grep -v grep | grep '/tmp/udevd' | awk '{print}' | xargs -I % echo  %` [p86]=`ps aux | grep -v grep | grep 'KCBjdXJsIC1vIC0gaHR0cDovLzg5LjIyMS41Mi4xMjIvcy5zaCApIHwgYmFzaCA' | awk '{print}' | xargs -I % echo  %` [p87]=`ps aux | grep -v grep | grep 'Y3VybCAtcyBodHRwOi8vMTA3LjE3NC40Ny4xNTYvbXIuc2ggfCBiYXNoIC1zaAo' | awk '{print}' | xargs -I % echo  %` [p88]=`ps aux | grep -v grep | grep 'sustse' | awk '{print}' | xargs -I % echo  %` [p89]=`ps aux | grep -v grep | grep 'sustse3' | awk '{print}' | xargs -I % echo  %` [p90]=`ps aux | grep -v grep | grep 'mr.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p91]=`ps aux | grep -v grep | grep 'mr.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p92]=`ps aux | grep -v grep | grep '2mr.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p93]=`ps aux | grep -v grep | grep '2mr.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p94]=`ps aux | grep -v grep | grep 'cr5.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p95]=`ps aux | grep -v grep | grep 'cr5.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p96]=`ps aux | grep -v grep | grep 'logo9.jpg' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p97]=`ps aux | grep -v grep | grep 'logo9.jpg' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p98]=`ps aux | grep -v grep | grep 'j2.conf' | awk '{print}' | xargs -I % echo  %` [p99]=`ps aux | grep -v grep | grep 'luk-cpu' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p100]=`ps aux | grep -v grep | grep 'luk-cpu' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p101]=`ps aux | grep -v grep | grep 'ficov' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p102]=`ps aux | grep -v grep | grep 'ficov' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p103]=`ps aux | grep -v grep | grep 'he.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p104]=`ps aux | grep -v grep | grep 'he.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p105]=`ps aux | grep -v grep | grep 'miner.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p106]=`ps aux | grep -v grep | grep 'miner.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p107]=`ps aux | grep -v grep | grep 'nullcrew' | grep 'wget' | awk '{print}' | xargs -I % echo  %` [p108]=`ps aux | grep -v grep | grep 'nullcrew' | grep 'curl' | awk '{print}' | xargs -I % echo  %` [p109]=`ps aux | grep -v grep | grep '107.174.47.156' | awk '{print}' | xargs -I % echo  %` [p110]=`ps aux | grep -v grep | grep '83.220.169.247' | awk '{print}' | xargs -I % echo  %` [p111]=`ps aux | grep -v grep | grep '51.38.203.146' | awk '{print}' | xargs -I % echo  %` [p112]=`ps aux | grep -v grep | grep '144.217.45.45' | awk '{print}' | xargs -I % echo  %` [p113]=`ps aux | grep -v grep | grep '107.174.47.181' | awk '{print}' | xargs -I % echo  %` [p114]=`ps aux | grep -v grep | grep '176.31.6.16' | awk '{print}' | xargs -I % echo  %` [p115]=`ps auxf | grep -v grep | grep "mine.moneropool.com" | awk '{print}' | xargs -I % echo  %` [p116]=`ps auxf | grep -v grep | grep "pool.t00ls.ru" | awk '{print}' | xargs -I % echo  %` [p117]=`ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:8080" | awk '{print}' | xargs -I % echo  %` [p118]=`ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:3333" | awk '{print}' | xargs -I % echo  %` [p119]=`ps auxf | grep -v grep | grep "zhuabcn@yahoo.com" | awk '{print}' | xargs -I % echo  %` [p120]=`ps auxf | grep -v grep | grep "monerohash.com" | awk '{print}' | xargs -I % echo  %` [p121]=`ps auxf | grep -v grep | grep "/tmp/a7b104c270" | awk '{print}' | xargs -I % echo  %` [p122]=`ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:6666" | awk '{print}' | xargs -I % echo  %` [p123]=`ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:7777" | awk '{print}' | xargs -I % echo  %` [p124]=`ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:443" | awk '{print}' | xargs -I % echo  %` [p125]=`ps auxf | grep -v grep | grep "stratum.f2pool.com:8888" | awk '{print}' | xargs -I % echo  %` [p126]=`ps auxf | grep -v grep | grep "xmrpool.eu" | awk '{print}' | xargs -I % echo  %` [p127]=`ps auxf | grep -v grep | grep "kieuanilam.me" | awk '{print}' | xargs -I % echo  %`)
for s in $(echo ${!pslist[*]});
do
        #echo "$a result is ${pslist[$a]}";
        if [ -n "${pslist[$s]}" ];then
                (echo "[!]发现恶意挖矿进程:" && echo "${pslist[$s]}")
        else
                #echo "[*]未发现恶意挖矿进程"
                for ((i=1;i<=100;i++));
                do
                        let z+=$i
                done
        fi
done
if [ "$z" -ge 0 ];then
        echo "[*]未发现恶意挖矿进程"
else
        echo ""
fi
printf "\n"

# pgrep-恶意挖矿进程
echo -e "\033[34m[-]pgrep查找恶意挖矿进程：\033[0m"
declare -A pglist
pglist=([pg1]=`pgrep -f monerohash | xargs -I % echo %` [pg2]=`pgrep -f L2Jpbi9iYXN | xargs -I % echo %` [pg3]=`pgrep -f xzpauectgr | xargs -I % echo %` [pg4]=`pgrep -f slxfbkmxtd | xargs -I % echo %` [pg5]=`pgrep -f mixtape | xargs -I % echo %` [pg6]=`pgrep -f addnj | xargs -I % echo %` [pg7]=`pgrep -f 200.68.17.196 | xargs -I % echo %` [pg8]=`pgrep -f IyEvYmluL3NoCgpzUG | xargs -I % echo %` [pg9]=`pgrep -f KHdnZXQgLXFPLSBodHRw | xargs -I % echo %` [pg10]=`pgrep -f FEQ3eSp8omko5nx9e97hQ39NS3NMo6rxVQS3 | xargs -I % echo %` [pg11]=`pgrep -f Y3VybCAxOTEuMTAxLjE4MC43Ni9saW4udHh0IHxzaAo | xargs -I % echo %` [pg12]=`pgrep -f mwyumwdbpq.conf | xargs -I % echo %` [pg13]=`pgrep -f honvbsasbf.conf | xargs -I % echo %` [pg14]=`pgrep -f mqdsflm.cf | xargs -I % echo %` [pg15]=`pgrep -f stratum | xargs -I % echo %` [pg16]=`pgrep -f lower.sh | xargs -I % echo %` [pg17]=`pgrep -f ./ppp | xargs -I % echo %` [pg18]=`pgrep -f cryptonight | xargs -I % echo %` [pg19]=`pgrep -f ./seervceaess | xargs -I % echo %` [pg20]=`pgrep -f ./servceaess | xargs -I % echo %` [pg21]=`pgrep -f ./servceas | xargs -I % echo %` [pg22]=`pgrep -f ./servcesa | xargs -I % echo %` [pg23]=`pgrep -f ./vsp | xargs -I % echo %` [pg24]=`pgrep -f ./jvs | xargs -I % echo %` [pg25]=`pgrep -f ./pvv | xargs -I % echo %` [pg26]=`pgrep -f ./vpp | xargs -I % echo %` [pg27]=`pgrep -f ./pces | xargs -I % echo %` [pg28]=`pgrep -f ./rspce | xargs -I % echo %` [pg29]=`pgrep -f ./haveged | xargs -I % echo %` [pg30]=`pgrep -f ./jiba | xargs -I % echo %` [pg31]=`pgrep -f ./watchbog | xargs -I % echo %` [pg32]=`pgrep -f ./A7mA5gb | xargs -I % echo %` [pg33]=`pgrep -f kacpi_svc | xargs -I % echo %` [pg34]=`pgrep -f kswap_svc | xargs -I % echo %` [pg35]=`pgrep -f kauditd_svc | xargs -I % echo %` [pg36]=`pgrep -f kpsmoused_svc | xargs -I % echo %` [pg37]=`pgrep -f kseriod_svc | xargs -I % echo %` [pg38]=`pgrep -f kthreadd_svc | xargs -I % echo %` [pg39]=`pgrep -f ksoftirqd_svc | xargs -I % echo %` [pg40]=`pgrep -f kintegrityd_svc | xargs -I % echo %` [pg41]=`pgrep -f jawa | xargs -I % echo %` [pg42]=`pgrep -f oracle.jpg | xargs -I % echo %` [pg43]=`pgrep -f 45cToD1FzkjAxHRBhYKKLg5utMGEN | xargs -I % echo %` [pg44]=`pgrep -f 188.209.49.54 | xargs -I % echo %` [pg45]=`pgrep -f 181.214.87.241 | xargs -I % echo %` [pg46]=`pgrep -f etnkFgkKMumdqhrqxZ6729U7bY8pzRjYzGbXa5sDQ | xargs -I % echo %` [pg47]=`pgrep -f 47TdedDgSXjZtJguKmYqha4sSrTvoPXnrYQEq2Lbj | xargs -I % echo %` [pg48]=`pgrep -f etnkP9UjR55j9TKyiiXWiRELxTS51FjU9e1UapXyK | xargs -I % echo %` [pg49]=`pgrep -f servim | xargs -I % echo %` [pg50]=`pgrep -f kblockd_svc | xargs -I % echo %` [pg51]=`pgrep -f native_svc | xargs -I % echo %` [pg52]=`pgrep -f ynn | xargs -I % echo %` [pg53]=`pgrep -f 65ccEJ7 | xargs -I % echo %` [pg54]=`pgrep -f jmxx | xargs -I % echo %` [pg55]=`pgrep -f 2Ne80nA | xargs -I % echo %` [pg56]=`pgrep -f sysstats | xargs -I % echo %` [pg57]=`pgrep -f systemxlv | xargs -I % echo %` [pg58]=`pgrep -f watchbog | xargs -I % echo %` [pg59]=`pgrep -f OIcJi1m | xargs -I % echo %`)
for g in $(echo ${!pglist[*]});
do
        #echo "$a result is ${pglist[$a]}";
        if [ -n "${pglist[$g]}" ];then
                (echo "[!]发现恶意挖矿进程:" && echo "${pglist[$g]}")
        else
                #echo "[*]未发现恶意挖矿进程"
                for ((i=1;i<=100;i++));
                do
                        let x+=$i
                done
        fi
done
if [ "$x" -ge 0 ];then
        echo "[*]未发现恶意挖矿进程"
else
        echo ""
fi
printf "\n"

# docker-恶意挖矿进程
echo -e "\033[34m[-]dcoker查找恶意挖矿进程：\033[0m"
declare -A docklist
which docker > /dev/null 2>&1
if [ $? == 0 ];then
	docklist=([d1]=`docker ps | grep "pocosow" | awk '{print}' | xargs -I % echo %` [d2]=`docker ps | grep "gakeaws" | awk '{print}' | xargs -I % echo %` [d3]=`docker ps | grep "azulu" | awk '{print}' | xargs -I % echo %` [d4]=`docker ps | grep "auto" | awk '{print}' | xargs -I % echo %` [d5]=`docker ps | grep "xmr" | awk '{print}' | xargs -I % echo %` [d6]=`docker ps | grep "mine" | awk '{print}' | xargs -I % echo %` [d7]=`docker ps | grep "monero" | awk '{print}' | xargs -I % echo %` [d8]=`docker ps | grep "slowhttp" | awk '{print}' | xargs -I % echo %` [d9]=`docker ps | grep "bash.shell" | awk '{print}' | xargs -I % echo %` [d10]=`docker ps | grep "entrypoint.sh" | awk '{print}' | xargs -I % echo %` [d11]=`docker ps | grep "/var/sbin/bash" | awk '{print}' | xargs -I % echo %` [d12]=`docker images -a | grep "pocosow" | awk '{print}'` [d13]=`docker images -a | grep "gakeaws" | awk '{print}'` [d14]=`docker images -a | grep "buster-slim" | awk '{print}'` [d15]=`docker images -a | grep "hello-" | awk '{print}'` [d16]=`docker images -a | grep "azulu" | awk '{print}'` [d17]=`docker images -a | grep "registry" | awk '{print}'` [d18]=`docker images -a | grep "xmr" | awk '{print}'` [d19]=`docker images -a | grep "auto" | awk '{print}'` [d20]=`docker images -a | grep "mine" | awk '{print}'` [d21]=`docker images -a | grep "monero" | awk '{print}'` [d22]=`docker images -a | grep "slowhttp" | awk '{print}'`)
	for k in $(echo ${!docklist[*]});
	do
        #echo "$a result is ${docklist[$a]}";
        if [ -n "${docklist[$k]}" ];then
                (echo "[!]发现恶意挖矿进程:" && echo "${docklist[$k]}")
        else
                #echo "[*]未发现恶意挖矿进程"
                for ((i=1;i<=100;i++));
                do
                        let h+=$i
                done
        fi
	done
	if [ "$h" -ge 0 ];then
		echo "[*]未发现恶意挖矿进程"
	else
		echo ""
    fi
    printf "\n"
else
	echo "[*]未发现docker命令..."
fi
echo -e "\033[34m[+]检查结束！\033[0m"
