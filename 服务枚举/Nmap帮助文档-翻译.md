有些扫描的详细介绍见:https://github.com/sanqiushugyh/Penetration-test-Service-enumerations/blob/master/%E6%9C%8D%E5%8A%A1%E6%9E%9A%E4%B8%BE/Nmap%E5%91%BD%E4%BB%A4%E8%AF%A6%E7%BB%86%E8%A7%A3%E9%87%8A.md
```python
"""
Nmap 7.70 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
 用法： nmap    [扫描类型]    [设置]        {目标 明确说明}
TARGET SPECIFICATION: 
 目标      明确说明  
  Can pass hostnames, IP addresses, networks, etc.
  能  传递   主机名  ,    IP地址    ,  网段   , 等等
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
 例如: 
  -iL <inputfilename>: Input from list of hosts/networks
         输入文件名   :      输入 主机/网段 列表   
  -iR <num hosts>: Choose random targets
        主机数量  :    选择随机的目标
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
      排除                             :   排除 主机/网段
  --excludefile <exclude_file>: Exclude list from file
      排除_文件                :  从文件中获得排除列表
HOST DISCOVERY:
  主机发现
  -sL: List Scan - simply list targets to scan
           简单地列出扫描的目标
  -sn: Ping Scan - disable port scan
ping探测扫描主机， 不进行端口扫描 （测试过对方主机把icmp包都丢弃掉，依然能检测到对方开机状态）
  -Pn: Treat all hosts as online -- skip host discovery
           认为所有主机在线        --   跳过主机发现
  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
               端口列表  :  指定端口的TCP SYN/ACK, UDP or SCTP 扫描
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
              ICMP反射,   时间戳  ,    掩码回复 的方式扫描
  -PO[protocol list]: IP Protocol Ping
         协议列表    : 使用 IP 协议包探测对方主机是否开启
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
              不进行域名解析     /    始终解析       [默认: 有时]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
                                   :  指定自定义DNS服务器
  --system-dns: Use OS's DNS resolver
              : 使用操作系统的DNS进行解析
  --traceroute: Trace hop path to each host
      路由追踪 : 追踪每个主机的跳跃路径
SCAN TECHNIQUES:
    扫描技术
  -sS/sT/sA/sW/sM: TCP SYN  /Connect()  /   ACK /Window/Maimon scans
                 :半开放扫描 /建立完整连接/是否过滤/ ..    / ..  
  -sU: UDP Scan
     : UDP 扫描
  -sN/sF/sX: TCP Null  , FIN, and Xmas scans
           : flag位全是0, .. , ..
  --scanflags <flags>: Customize TCP scan flags
   扫描标志位         :   定制的TCP扫描标志位
  -sI <zombie host[:probeport]>: Idle scan
         僵尸主机  [:探测端口]  : 空闲扫描
  -sY/sZ: SCTP INIT  /COOKIE-ECHO scans
        :半开SCTP关联/ ...
  -sO: IP protocol scan
     :IP协议扫描
  -b <FTP relay host>: FTP bounce scan
       FTP中继主机    ： FTP反弹扫描
PORT SPECIFICATION AND SCAN ORDER:
        端口说明和扫描顺序
  -p <port ranges>: Only scan specified ports
     <  端口范围  >:   只扫描指定端口
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
      排除-端口    <  端口范围 >:   从扫描中排除指定的端口
  -F: Fast mode - Scan fewer ports than the default scan
    :  快速模式  -       比默认端口数量少
  -r: Scan ports consecutively - don't randomize
    :     连续的扫描端口        -    不要随机扫描
  --top-ports <number>: Scan <number> most common ports
    高危的端口 < 数量 >:    扫描一定量的高危端口
  --port-ratio <ratio>: Scan ports more common than <ratio>
    端口-比例   <比例0-1> :  按概率来扫描   
SERVICE/VERSION DETECTION:
   服务/版本 发现:
  -sV: Probe open ports to determine service/version info
                      探测打开的端口以确定服务/版本信息
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
   版本扫描-程度       <级别> :    设置从 0 (轻度)   到9 (高强度)
  --version-light: Limit to most likely probes (intensity 2)
    版本扫描-轻度 :   最高到强度2
  --version-all: Try every single probe (intensity 9)
   版本扫描-重度:  尝试每一个探针(强度9)
  --version-trace: Show detailed version scan activity (for debugging)
    版本扫描-追踪 :       显示详细的版本扫描过程            (用来debug)
SCRIPT SCAN:
   脚本扫描
  -sC: equivalent to --script=default
     :     等价于     --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of directories, script-files or script-categories
            <Lua 脚本>  :    <Lua 脚本>      是一个以逗号分割的列表关于    目录,        脚本文件     或脚本类别
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
      脚本参数                      :    为脚本提供参数
  --script-args-file=filename: provide NSE script args in a file
                                   在文件中提供NSE脚本参数
  --script-trace: Show all data sent and received
                     显示所有发送和接收的数据
  --script-updatedb: Update the script database.
                           更新脚本数据库。
  --script-help=<Lua scripts>: Show help about scripts.
                                 显示有关脚本的帮助。
           <Lua scripts> is a comma-separated list of script-files or script-categories.
           <Lua scripts> 是脚本文件或脚本类别的逗号分隔列表。
OS DETECTION:
操作系统检测
  -O: Enable OS detection
        启用操作系统检测
  --osscan-limit: Limit OS detection to promising targets
                     将OS检测限制为有希望的目标
  --osscan-guess: Guess OS more aggressively
                         更有攻击性地猜测OS
TIMING AND PERFORMANCE:
         时间和性能
  Options which take <time> are in seconds, or append 'ms' (milliseconds), 's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
       设置占用时间         以s(秒)为单位,           或     ms(毫秒),         s(秒),       m(分钟),        h(小时)
  -T<0-5>: Set timing template (higher is faster)
             设置计时模板(越高越快)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
                                         并行主机扫描组大小
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
                                                  探针并行
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies probe round trip time.
指定探头往返时间。
  --max-retries <tries>: Caps number of port scan probe retransmissions.
                             Caps端口扫描探测重传次数。
  --host-timeout <time>: Give up on target after this long
                                  多久后放弃探测
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
                                        调整探测之间的延迟
  --min-rate <number>: Send packets no slower than <number> per second
                             每秒不慢于<number>发送数据包
  --max-rate <number>: Send packets no faster than <number> per second
                        每秒发送数据包的速度不超过<number>
FIREWALL/IDS EVASION AND SPOOFING:
  防火墙/IDS      规避和欺骗
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
                      数据包分段     (可选，具有给定的MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
                                用诱饵掩盖扫描
  -S <IP_Address>: Spoof source address
                          源地址欺骗
  -e <iface>: Use specified interface
               使用指定的接口
  -g/--source-port <portnum>: Use given port number
                              使用给定的端口号
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
                               通过HTTP/SOCKS4代理的中继连接
  --data <hex string>: Append a custom payload to sent packets
                       将自定义负载附加到已发送的数据包
  --data-string <string>: Append a custom ASCII string to sent packets
                              将自定义ASCII字符串附加到已发送的数据包
  --data-length <num>: Append random data to sent packets
                            填充随机数据让数据包长度达到 NUM
  --ip-options <options>: Send packets with specified ip options
                         发送具有指定IP选项的数据包
  --ttl <val>: Set IP time-to-live field
              设置IP报文生存时间字段
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
                                              MAC 地址伪装
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
           发送带有虚假TCP/UDP/SCTP校验和的数据包
OUTPUT:
输出选项
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.
                         将标准输出直接写入指定的文件 -oX ：输出 xml 文件 。-oS ：将所有的输出都改为大写 。-oG ：输出便于通过 bash 或者 perl 处理的格式,非 xml 。
  -oA <basename>: Output in the three major formats at once
             可将扫描结果以标准格式、XML 格式和 Grep 格式一 次性输出 。
  -v: Increase verbosity level (use -vv or more for greater effect)
         提高输出的详细程度      (使用-vv或更多以获得更大的效果)
  -d: Increase debugging level (use -dd or more for greater effect)
      提高调试级别              (使用-dd或更多以获得更大效果)
  --reason: Display the reason a port is in a particular state
            显示端口处于特定状态的原因
  --open: Only show open (or possibly open) ports
          仅显示打开(或可能打开)的端口
  --packet-trace: Show all packets sent and received
                   显示所有发送和接收的数据包
  --iflist: Print host interfaces and routes (for debugging)
          打印主机接口和路由(用于调试)
  --append-output: Append to rather than clobber specified output files
                 附加到指定的输出文件，而不是删除指定的输出文件
  --resume <filename>: Resume an aborted scan
                       恢复已中止的扫描
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
                           用于将XML输出转换为HTML的XSL样式表
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
                从Nmap.Org引用样式表以获得更可移植的XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
                        防止将XSL样式表与XML输出相关联
MISC:
杂项
  -6: Enable IPv6 scanning
           使用IPv6扫描
  -A: Enable OS detection, version detection, script scanning, and traceroute
        启用OS检测、版本检测、脚本扫描和traceroute
  --datadir <dirname>: Specify custom Nmap data file location
                          指定自定义Nmap数据文件位置
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
                              使用原始以太网帧或IP数据包发送
  --privileged: Assume that the user is fully privileged
                  假设用户具有完全特权
  --unprivileged: Assume the user lacks raw socket privileges
                假设用户缺少原始套接字权限
  -V: Print version number
        打印版本号
  -h: Print this help summary page.
              打印此帮助摘要页。
EXAMPLES:
    示例
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (https://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES
root@Sanqiushu:~# 

```
感谢所有前辈:

http://blog.chinaunix.net/uid-28811518-id-5599390.html
https://www.jianshu.com/p/18b80024fb7d
https://zhuanlan.zhihu.com/p/25612351
https://www.cnblogs.com/nmap/p/6232969.html

比较详细:https://www.tuicool.com/articles/7ZVFjea
https://blog.csdn.net/chen_jianjian/article/details/52487950
