#!/bin/bash
echo "

	
                         ____ _  _ ____ ____ ____ ____ _  _ ____ _   _ 
                           |___ |\/| |___ |__/ | __ |___ |\ | |     \_/  
                           |___ |  | |___ |  \ |__] |___ | \| |___   |  

                                        Powered by Vampire                                           

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
echo -e "\033[34m[-]/etc/passwd:\033[0m" #blue
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
port=`netstat -antup` # port=`netstat -antlp | grep -ni "ESTABLISHED"`
echo -e "\033[34m[-]连接端口状态:：\033[0m"
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
shell=`cat ~/.bash_history | grep -e "chmod" -e "rm" -e "wget" -e "ssh" -e "tar" -e "zip" -e "scp"`
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
ls /tmp /var/tmp /dev/shm -alht | tee -a $filename
echo -e "\n" | tee -a $filename

# SSH KEY敏感信息
echo -e "\033[34m[-]SSH key信息：\033[0m" | tee -a $filename
sshkey=${HOME}/.ssh/authorized_keys
if [ -e "${sshkey}" ]; then
    cat ${sshkey} | tee -a $filename
else
    echo -e "SSH key文件不存在\n" | tee -a $filename
fi
echo -e "\n" | tee -a $filename

# 显示Rootkit内核模块信息
echo -e "\033[34m[-]Rootkit内核模块信息：\033[0m" | tee -a $filename
kernel=$(cat /proc/kallsyms | egrep 'hide_tcp4_port|hidden_files|hide_tcp6_port')
if [ -n "$kernel" ]; then
	echo "存在内核敏感函数！ 疑似Rootkit内核模块" | tee -a $filename
else
	echo "未找到内核敏感函数" | tee -a $filename
fi
echo -e "\n" | tee -a $filename

# netstat-恶意挖矿进程
echo -e "\033[34m[-]netstat查找恶意挖矿进程：\033[0m"
netstat -anp | grep 185.71.65.238 | awk '{print}'
netstat -anp | grep 140.82.52.87 | awk '{print}'
netstat -antp | grep '46.243.253.15' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print}'
netstat -antp | grep '176.31.6.16' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print}'
netstat -anp | grep :443 | awk '{print}'  
netstat -anp | grep :23 | awk '{print}'   
netstat -anp | grep :143 | awk '{print}'  
netstat -anp | grep :2222 | awk '{print}'  
netstat -anp | grep :3333 | awk '{print}'  
netstat -anp | grep :3389 | awk '{print}'  
netstat -anp | grep :4444 | awk '{print}'  
netstat -anp | grep :5555 | awk '{print}'  
netstat -anp | grep :6666 | awk '{print}'  
netstat -anp | grep :6665 | awk '{print}'  
netstat -anp | grep :6667 | awk '{print}'  
netstat -anp | grep :7777 | awk '{print}'  
netstat -anp | grep :8444 | awk '{print}'  
netstat -anp | grep :3347 | awk '{print}'
netstat -anp | grep :14433 | awk '{print}'
printf "\n"

# ps-恶意挖矿进程
echo -e "\033[34m[-]ps查找恶意挖矿进程：\033[0m"
ps aux | grep -v grep | grep ':3333' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep ':5555' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'kworker -c\\' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'log_' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'systemten' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'voltuned' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'darwin' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '/tmp/dl' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '/tmp/ddg' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '/tmp/pprt' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '/tmp/ppol' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '/tmp/65ccE*' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '/tmp/jmx*' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '/tmp/2Ne80*' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'IOFoqIgyC0zmf2UR' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '45.76.122.92' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '51.38.191.178' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep '51.15.56.161' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '86s.jpg' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'aGTSGJJp' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'nMrfmnRa' | awk '{print}' | xargs -I % echo %
ps aux | grep -v grep | grep 'PuNY5tm2' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'I0r8Jyyt' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'AgdgACUD' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'uiZvwxG8' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'hahwNEdB' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'BtwXn5qH' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '3XEzey2T' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 't2tKrCSZ' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'HD7fcBgg' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'zXcDajSs' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '3lmigMo' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'AkMK4A2' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'AJ2AkKe' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'HiPxCJRS' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'http_0xCC030' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'http_0xCC031' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'http_0xCC032' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'http_0xCC033' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "C4iLM4L" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'aziplcr72qjhzvin' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | awk '{ if(substr($11,1,2)=="./" && substr($12,1,2)=="./") print $2 }' | xargs -I % echo  %
ps aux | grep -v grep | grep '/boot/vmlinuz' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "i4b503a52cc5" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "dgqtrcst23rtdi3ldqk322j2" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "2g0uv7npuhrlatd" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "nqscheduler" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "rkebbwgqpl4npmm" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep -v aux | grep "]" | awk '$3>10.0{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "2fhtu70teuhtoh78jc5s" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "0kwti6ut420t" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "44ct7udt0patws3agkdfqnjm" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep -v "/" | grep -v "-" | grep -v "_" | awk 'length($11)>19{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "\[^" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "rsync" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "watchd0g" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | egrep 'wnTKYg|2t3ik|qW3xT.2|ddg' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "158.69.133.18:8220" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "/tmp/java" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'gitee.com' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '/tmp/java' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '104.248.4.162' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '89.35.39.78' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '/dev/shm/z3.sh' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'kthrotlds' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'ksoftirqds' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'netdns' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'watchdogs' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'kdevtmpfsi' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'kinsing' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'redis2' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep -v root | grep -v dblaunch | grep -v dblaunchs | grep -v dblaunched | grep -v apache2 | grep -v atd | grep -v kdevtmpfsi | awk '$3>80.0{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep -v aux | grep " ps" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep "sync_supers" | cut -c 9-15 | xargs -I % echo  %
ps aux | grep -v grep | grep "cpuset" | cut -c 9-15 | xargs -I % echo  %
ps aux | grep -v grep | grep -v aux | grep "x]" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep -v aux | grep "sh] <" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep -v aux | grep " \[]" | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '/tmp/l.sh' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '/tmp/zmcat' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'hahwNEdB' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'CnzFVPLF' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'CvKzzZLs' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'aziplcr72qjhzvin' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '/tmp/udevd' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'KCBjdXJsIC1vIC0gaHR0cDovLzg5LjIyMS41Mi4xMjIvcy5zaCApIHwgYmFzaCA' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'Y3VybCAtcyBodHRwOi8vMTA3LjE3NC40Ny4xNTYvbXIuc2ggfCBiYXNoIC1zaAo' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'sustse' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'sustse3' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'mr.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'mr.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '2mr.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '2mr.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'cr5.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'cr5.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'logo9.jpg' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'logo9.jpg' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'j2.conf' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'luk-cpu' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'luk-cpu' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'ficov' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'ficov' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'he.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'he.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'miner.sh' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'miner.sh' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'nullcrew' | grep 'wget' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep 'nullcrew' | grep 'curl' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '107.174.47.156' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '83.220.169.247' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '51.38.203.146' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '144.217.45.45' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '107.174.47.181' | awk '{print}' | xargs -I % echo  %
ps aux | grep -v grep | grep '176.31.6.16' | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "mine.moneropool.com" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "pool.t00ls.ru" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:8080" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:3333" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "zhuabcn@yahoo.com" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "monerohash.com" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "/tmp/a7b104c270" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:6666" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:7777" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:443" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "stratum.f2pool.com:8888" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "xmrpool.eu" | awk '{print}' | xargs -I % echo  %
ps auxf | grep -v grep | grep "kieuanilam.me" | awk '{print}' | xargs -I % echo  %
printf "\n"

# pgrep-恶意挖矿进程
echo -e "\033[34m[-]pgrep查找恶意挖矿进程：\033[0m"
pgrep -f monerohash | xargs -I % echo %
pgrep -f L2Jpbi9iYXN | xargs -I % echo %
pgrep -f xzpauectgr | xargs -I % echo %
pgrep -f slxfbkmxtd | xargs -I % echo %
pgrep -f mixtape | xargs -I % echo %
pgrep -f addnj | xargs -I % echo %
pgrep -f 200.68.17.196 | xargs -I % echo %
pgrep -f IyEvYmluL3NoCgpzUG | xargs -I % echo %
pgrep -f KHdnZXQgLXFPLSBodHRw | xargs -I % echo %
pgrep -f FEQ3eSp8omko5nx9e97hQ39NS3NMo6rxVQS3 | xargs -I % echo %
pgrep -f Y3VybCAxOTEuMTAxLjE4MC43Ni9saW4udHh0IHxzaAo | xargs -I % echo %
pgrep -f mwyumwdbpq.conf | xargs -I % echo %
pgrep -f honvbsasbf.conf | xargs -I % echo %
pgrep -f mqdsflm.cf | xargs -I % echo %
pgrep -f stratum | xargs -I % echo %
pgrep -f lower.sh | xargs -I % echo %
pgrep -f ./ppp | xargs -I % echo %
pgrep -f cryptonight | xargs -I % echo %
pgrep -f ./seervceaess | xargs -I % echo %
pgrep -f ./servceaess | xargs -I % echo %
pgrep -f ./servceas | xargs -I % echo %
pgrep -f ./servcesa | xargs -I % echo %
pgrep -f ./vsp | xargs -I % echo %
pgrep -f ./jvs | xargs -I % echo %
pgrep -f ./pvv | xargs -I % echo %
pgrep -f ./vpp | xargs -I % echo %
pgrep -f ./pces | xargs -I % echo %
pgrep -f ./rspce | xargs -I % echo %
pgrep -f ./haveged | xargs -I % echo %
pgrep -f ./jiba | xargs -I % echo %
pgrep -f ./watchbog | xargs -I % echo %
pgrep -f ./A7mA5gb | xargs -I % echo %
pgrep -f kacpi_svc | xargs -I % echo %
pgrep -f kswap_svc | xargs -I % echo %
pgrep -f kauditd_svc | xargs -I % echo %
pgrep -f kpsmoused_svc | xargs -I % echo %
pgrep -f kseriod_svc | xargs -I % echo %
pgrep -f kthreadd_svc | xargs -I % echo %
pgrep -f ksoftirqd_svc | xargs -I % echo %
pgrep -f kintegrityd_svc | xargs -I % echo %
pgrep -f jawa | xargs -I % echo %
pgrep -f oracle.jpg | xargs -I % echo %
pgrep -f 45cToD1FzkjAxHRBhYKKLg5utMGEN | xargs -I % echo %
pgrep -f 188.209.49.54 | xargs -I % echo %
pgrep -f 181.214.87.241 | xargs -I % echo %
pgrep -f etnkFgkKMumdqhrqxZ6729U7bY8pzRjYzGbXa5sDQ | xargs -I % echo %
pgrep -f 47TdedDgSXjZtJguKmYqha4sSrTvoPXnrYQEq2Lbj | xargs -I % echo %
pgrep -f etnkP9UjR55j9TKyiiXWiRELxTS51FjU9e1UapXyK | xargs -I % echo %
pgrep -f servim | xargs -I % echo %
pgrep -f kblockd_svc | xargs -I % echo %
pgrep -f native_svc | xargs -I % echo %
pgrep -f ynn | xargs -I % echo %
pgrep -f 65ccEJ7 | xargs -I % echo %
pgrep -f jmxx | xargs -I % echo %
pgrep -f 2Ne80nA | xargs -I % echo %
pgrep -f sysstats | xargs -I % echo %
pgrep -f systemxlv | xargs -I % echo %
pgrep -f watchbog | xargs -I % echo %
pgrep -f OIcJi1m | xargs -I % echo %
printf "\n"

# docker-恶意挖矿进程
echo -e "\033[34m[-]dcoker查找恶意挖矿进程：\033[0m"
which docker > /dev/null 2>&1
if [ $? == 0 ];then
	docker ps | grep "pocosow" | awk '{print}' | xargs -I % echo %
	docker ps | grep "gakeaws" | awk '{print}' | xargs -I % echo %
	docker ps | grep "azulu" | awk '{print}' | xargs -I % echo %
	docker ps | grep "auto" | awk '{print}' | xargs -I % echo %
	docker ps | grep "xmr" | awk '{print}' | xargs -I % echo %
	docker ps | grep "mine" | awk '{print}' | xargs -I % echo %
	docker ps | grep "monero" | awk '{print}' | xargs -I % echo %
	docker ps | grep "slowhttp" | awk '{print}' | xargs -I % echo %
	docker ps | grep "bash.shell" | awk '{print}' | xargs -I % echo %
	docker ps | grep "entrypoint.sh" | awk '{print}' | xargs -I % echo %
	docker ps | grep "/var/sbin/bash" | awk '{print}' | xargs -I % echo %
	docker images -a | grep "pocosow" | awk '{print}'
	docker images -a | grep "gakeaws" | awk '{print}'
	docker images -a | grep "buster-slim" | awk '{print}'
	docker images -a | grep "hello-" | awk '{print}'
	docker images -a | grep "azulu" | awk '{print}'
	docker images -a | grep "registry" | awk '{print}'
	docker images -a | grep "xmr" | awk '{print}'
	docker images -a | grep "auto" | awk '{print}'
	docker images -a | grep "mine" | awk '{print}'
	docker images -a | grep "monero" | awk '{print}'
	docker images -a | grep "slowhttp" | awk '{print}'
	printf "\n"
else
	echo "未发现docker命令..."
fi
echo -e "\033[34m[+]检查结束！\033[0m"
