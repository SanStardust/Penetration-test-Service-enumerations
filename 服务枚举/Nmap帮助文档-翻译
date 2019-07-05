有些扫描的详细介绍见:https://www.jianshu.com/p/0f0ca4f4b18d
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
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
  -F: Fast mode - Scan fewer ports than the default scan
  -r: Scan ports consecutively - don't randomize
  --top-ports <number>: Scan <number> most common ports
  --port-ratio <ratio>: Scan ports more common than <ratio>
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second
FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
  --iflist: Print host interfaces and routes (for debugging)
  --append-output: Append to rather than clobber specified output files
  --resume <filename>: Resume an aborted scan
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --datadir <dirname>: Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
  --privileged: Assume that the user is fully privileged
  --unprivileged: Assume the user lacks raw socket privileges
  -V: Print version number
  -h: Print this help summary page.
EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (https://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES
root@Sanqiushu:~# ^C

```
感谢所有前辈:
http://blog.chinaunix.net/uid-28811518-id-5599390.html
https://www.jianshu.com/p/18b80024fb7d
https://zhuanlan.zhihu.com/p/25612351
https://www.cnblogs.com/nmap/p/6232969.html
比较详细:https://www.tuicool.com/articles/7ZVFjea
