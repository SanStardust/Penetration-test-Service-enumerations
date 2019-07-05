# 网络扫描工具
##Nmap
默认的扫描项目：
```
Intense scan                ->  强力扫描                 ->   nmap -T4 -A -v 192.168.0.107                     ->  -A 就代表强力扫描 T4 代表第四个时间等级
Intense scan plus UDP       ->  强力扫描UDP              ->   nmap -sS -sU -T4 -A -v 192.168.0.107             ->  -sS 半开扫描  -sU UDP扫描
Intense scan, all TCP ports ->  强力扫描所有TCP端口       ->   nmap -p 1-65535 -T4 -A -v 192.168.0.107          -> -p 指定端口
Intense scan, no ping       ->  强力扫描，不使用ping检测   ->  nmap -T4 -A -v -Pn 192.168.0.107                 ->  -Pn 禁用ping检测
Ping scan                   ->  ping检测                  ->  nmap -sn 192.168.0.107                           -> -sn Null扫描（不确定）
Quick scan                  ->  快速扫描                  ->  nmap -T4 -F 192.168.0.107                        ->  -F 快速扫描
Quick scan plus             ->  快速扫描plus              ->  nmap -sV -T4 -O -F --version-light 192.168.0.107  ->  -sV 服务版本识别  -O 操作系统检测 
Quick traceroute            ->  快速检测路由              ->  nmap -sn --traceroute 192.168.0.107               ->  --traceroute 路由检测
Regular scan                ->  正常扫描                 ->  nmap 192.168.0.107                                 ->  
Slow comprehensive scan     ->  慢速综合扫描             ->  nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" 192.168.0.107

```
主机探测、服务/版本检测、操作系统检测、网络路由跟踪、Nmap脚本引擎
- tcp 扫描 -sT
这种方式最简单。直接与被扫描的端口建立tcp链接，如果成功，则说明端口开放，如果不成功则说明端口关闭的。这种扫描的特点是与被扫描端口建立完成的tcp链接，完整的tcp三次握手。优点主要是不需要root权限即可扫描端口。因为connect可以在用户态直接调用
- TCP SYN 扫描  -sS
这种扫描方式又被称为tcp半开放扫描。顾名思义，这种扫描不需要建立完整的tcp连接，即可扫描端口的状态。发送tcp syn数据包，这个也是tcp握手的第一个包。如果端口开放，则会返回 tcp syn+ack数据包。如果端口关闭，则返回 tcp rst数据包。这样我们就不用进行tcp 握手的第三步，也可以探测端口的状态。这种扫描需要构建raw socket。所以需要root权限
- TCP FIN 扫描 -sF
有些时候防火墙绘过滤tcp syn数据包，有些时候会记录syn数据包并检测时候有nmap扫描。这时候可以使用TCP FIN scanning。这种方式很简单。发送tcp FIN数据包到待测端口。如果返回RST数据包，则说明该端口关闭，如果无返回则说明该端口开放。这时tcp协议的一个BUG，所以这种扫描方式不一定百分之百可靠（例如windows），但是这种扫描方式适合大部分 *NIX 系统。
- TCP NULL, FIN, and Xmas 扫描  -sN  -sF  -sX
在RFC 793的第65页写到，如果目的端口的是关闭的，并且接受到的tcp数据包如果可能会导致系统错误，则返回RST。如果开放的端口接受到诸如SYN RST ACK，则丢弃或者不做任何处理。根据此RFC描述，我们可以发送不包含SYN RST或者ACK标志的数据包，如果返回RST则说明端口是关闭状态，如果什么都没有返回则说明端口是开放状态。
Null scan tcp flag headers 全为0
FIN scan 只设置tcp FIN标志
xmas scan 同时设置FIN PSH URG标志位。

上面这三种扫描的结果都是一致的，如果接受到到RST，则说明端口是关闭的。如果无响应，则端口可能是开放或者filteted状态。如果返回icmp unreachable error(type 3, code 0, 1, 2, 3, 9, 10, 13)，则说明端口一定是filtered的。
- TCP ACK scan  -sA
这种扫描只设置tcp ack标志位。这种扫描一般来探测防火墙是否过滤被扫描的端口。如果扫描的端口未被防火墙保护，那么无论是开放或者是关闭，都会返回RST。nmap将该端口标记为未被封锁的（unfiltered），但是不能确定该端口是开放或者关闭状态。如果无响应，或者返货icmp error，则该端口一定被防火墙封锁了
- TCP Window scan  -sW
tcp窗口扫描，如果接收到RST，则说明端口封锁了。在某些操作系统，开放的端口会返回一个正数的tcp窗口值，如果端口关闭，则返回tcp窗口值为0或者负数。但是这种扫描不是很靠谱
- TCP Maimon scan   -sM
这种扫描为发送同时设置FIN/ACK的数据包。如果返回RST，则说明端口是开放的，如果无响应，则是关闭状态的。
- UDP scanning  -sU
由于系统限制，UDP美妙只能发送1次 ICMP Port Unreachable信息，
但是可以通过一下的方法加速扫描过程
进行并发的扫描、优先扫描常用的端口、在防火墙后面扫描、启用--host--timeout选项跳过响应过慢的主机
TCP Maimon Scan
Maimon Scan 以其发现者 Uriel Maimon 命名。 他在 Phrack 杂志第49期（1996年11月）中描述了这种技术。 除了探测器是FIN / ACK之外，此技术与NULL，FIN和Xmas扫描完全相同。 根据RFC 793（TCP），响应于这样的探测，应该生成RST分组，无论端口是打开还是关闭。 但是，如果端口打开，许多BSD派生系统只会丢弃数据包。 Nmap利用这一点来确定开放端口，如下表所示：

Nmap 对 TCP Maimon Scan 的处理： -sM

Probe Response	Assigned State
No response received (even after retransmissions)	`open	filtered`
TCP RST packet	closed
ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)	filtered
![-sN](https://upload-images.jianshu.io/upload_images/12067578-59f5928d1af3bb9f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![image.png](https://upload-images.jianshu.io/upload_images/12067578-c52cb7dac406d86d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![image.png](https://upload-images.jianshu.io/upload_images/12067578-6bee16e725e1f600.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
## TCP Idle Scan

1998年，安全研究员Antirez（曾参与编辑nmap中有关hping2工具的相关文章）在Bugtraq邮件列表中发布了一篇关于新的端口扫描技术的文章。Idle Scan，也就慢慢的为众人所了解，它允许进行完全盲目的端口扫描。事实上，攻击者可以不用向目标发送数据包就完成扫描工作！相反，用猥琐的边信道攻击是能够让扫描映射到一个Zombie 主机上的。除了极其隐蔽的情况，这种扫描方式允许挖掘机器之间基于IP的信任关系。

虽然 Idle Scan 比目前讨论的任何技术都复杂，但您无需成为TCP / IP专家就能理解它。你只需要知道这些就够了：

*   确定TCP端口是否打开的一种方法是向端口发送SYN（会话建立）数据包。如果端口打开，目标机器将响应SYN / ACK（会话请求确认）数据包，如果端口关闭，则响应RST（重置）。这是前面讨论的SYN扫描的基础。
*   接收未经请求的SYN / ACK数据包的计算机将使用RST进行响应。未经请求的RST将被忽略。

*   Internet上的每个IP数据包都有一个片段标识号（IP ID）。由于许多操作系统只是为它们发送的每个数据包递增此数字，因此探测IPID可以告诉攻击者自上次探测以来已发送了多少数据包。

结合以上特征，就可以伪造身份去扫描目标网络，所以看起来就像是无辜的 Zombie 主机在扫描。

### Idle Scan Step by Step

从本质上来看，Idle Scan 只需要重复3个步骤就ok了。

1.  探查Zombie的IP ID并记录下来。
2.  在Zombie主机上伪造一个包，然后把包发送给目标主机端口。根据端口的状态，目标主机可能会也有可能不会导致Zombie主机IPID值增加。
3.  再探查Zombie主机的IP ID。比较两次得到IPID值

经过这样一个流程，Zombie主机的 IP ID 应该会增加1~2。如果只是增加了1，那么就可以说明Zombie主机还没有发出任何包，当然，响应攻击者的探查请求除外。没有发送包也就意味着目标端口没有被打开（也可能是目标主机向Zombie主机发送了一个RST包，导致请求被忽略，或者是根本就是什么都没有做）。增加的如果是2，那就表明Zombie主机成功在两个探测器之间发送了包。这种情况一般情况都意味着目标端口是开着的（目标大概会向Zombie主机发送一个SYN/ACK包去响应攻击者伪造的SYN，从Zombie主机诱导RST包）。如果是增加了一个比2还大的数字，那么就说明Zombie主机太糟糕了！它可能不能胜任预测IPID数值，也可能是正在忙于其他与Idle Scan无关的事情。

虽然关闭了端口和被过滤的端口会发生的事情稍微有点点不同，但是攻击者处理的方法都一样，IPID都只是增加1。所以，在Idel Scan中无法区别端口到底是关闭的还是已经过滤了。当Nmap记录的IPID增加了1，也就被标记成了close丨filterred。

以下三张图大略可以说明端口被打开，关闭，过滤的情况。

端口开放：

![image](https://upload-images.jianshu.io/upload_images/12067578-cceb4c308f0890d0.png!web?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

端口关闭：

![image](https://upload-images.jianshu.io/upload_images/12067578-13ec741613846539.png!web?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

端口被过滤：

![image](https://upload-images.jianshu.io/upload_images/12067578-75cddde289d1247c.png!web?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

Idel Scan根本上来讲就是一个隐性扫描，Nmap提供了decoy scanning (-D)，帮助使用者保护自己的身份。如果不是使用的（类似Idel Scan扫描方式）仍然需要攻击者通过自身真实IP向目标发送数据包以获取扫描结果。Idel Scan扫描结果其中之一就有入侵检测系统通常会发送一个Zombie主机已经开始扫描的通知。所以它可以作为一个框架去扫描另外一个目标，当你查阅入侵检测系统（IDS）时，请记住这种可能性。

Idel Scan的一个独特优势便是，它可以绕开某些过滤防火墙和路由器。IP源地址过滤，是一种常见的（虽然很弱）用于限制机器连接到敏感主机或者说网络上的安全机制。举个例子，一个公司数据库服务器，只允许公共网络连接。或者，家庭用户只允许SSH连接到工作机上面。

Idel Scanning有时也可以被用来映射信任关系，关键在于Idel Scan最终会从Zombie主机获取开放端口列表。一个正常的扫描对于上述数据库服务器可能会显示没有端口开放，但是当将Zombie主机作为Web Sever的IP，使用Idel Scan就可能将数据库相关开放端口暴露出来。

映射出的这些信任关系就可能作为攻击者优先考虑的目标，上面所讨论的方式手法很猥琐哇！

Idel Scan有一个缺点就是它比其他一些扫描方式所花费的时间更长。尽管在《 [Idel Scan算法实现](http://nmap.org/book/idlescan.html#scan-methods-idle-scan-algorithms) 》章节中有对Idel Scan的优化算法，一个只需要15秒就可以完成的SYN，Idel Scan或许需要15分钟才能够完成。另一个问题就是你必须能够发送欺骗包，伪装成好像他们来自Zombie主机一般，让他们到达目标主机。许多ISP服务商（特别是拨号和住宅宽带供应商）目前执行出口过滤来防止这类数据包欺骗。高端供应商（比如说主机托管，T1-Services）就不太可能这么做。如果实际存在这个过滤，Nmap会在你尝试的每一个Zombie主机上显示一个快速错误消息。如果不能够更换ISP服务商，那么最好尝试在让ISP服务商给你更换一个IP。有时候这个过滤仅仅只是阻止了客户使用范围之外的欺骗IP地址。Idel Scan另外一个难点就是你必须寻找一个正在工作的Zombie主机。

上述描述的是Idel Scan的基础水平。在Nmap上实现却是有些复杂，最关键的差异在于Nmap能够同时执行，而且误报少。

Parallelizing idle scan由于是间接推导出端口所以，他比其他扫描方式要更加的猥琐。如果Nmap探测目标主机上的多个端口，然后检测Zombie主机上新的IP ID值，IP ID的值增加了多少就显示出目标开放了多少个端口。实际上这并不是一个和严重的问题，绝大多数端口在大型扫描结果中基本上都是被关闭或者被过滤。由于只有开放端口才可以让IP ID值增加，Nmap会认为没有增加量，然后整个组的端口就被标记成了关闭或者被过滤。Nmap可以并行扫描一百组端口。如果Nmap在探测一组端口的时候Zombie主机IP ID同时也增加了，就说明在这一组端口中一定有开放的端口。Nmap继而使用二进制搜索发现开放的端口。它将数据组分成两份，分别发送探测信息，如果一个数据组显示没有开放端口，那么这一数据组的端口都将被标记为被关闭或者被过滤。如果一个数据组显示有开放端口，那么在把这个数据组分成两份，重复以上步骤，直到最终将开放端口都找出来。虽然这种方式更复杂，但是这种方式可以节约扫描时间。

可靠性是Idel Scan的另一个问题。如果Zombie主机在扫描时向任何不相干的机器发送数据包，其IP ID会增加。这就会让Nmap误以为已经寻找到开放的端口了。幸运的是，并行扫描在这里也是有很大作用的。如果Nmap在一个组中扫描100个端口，那么IP ID就会增加标识两个开放端口，Nmap将这组数据分成50端口一个小组。当Nmap同时在两个小组中进行IP ID扫描时，Zombie主机IP ID总的增加量就在加了一次。另外，Nmap如果探测到不一致，那么它会重新探测。基于检测可靠的Zombie主机，Nmap还会修改组大小以及扫描时间。如果Nmap发现有大量不一致的结果，它将退出，并提示用户选择更好的Zombie主机。

具体操作可以参考 [TCP Idle Scan (-sI)](https://nmap.org/book/idlescan.html)
####SCTP INIT scan
SCTP INIT扫描是TCP SYN扫描的SCTP等效物。它可以快速执行，在快速网络上每秒扫描数千个端口，而不受限制性防火墙的限制。与SYN扫描一样，INIT扫描相对不显眼且隐蔽，因为它永远不会完成SCTP关联。它还允许在打开，关闭和过滤状态之间进行清晰，可靠的区分。

此技术通常称为半开扫描，因为您不打开完整的SCTP关联。您发送一个INIT块，就好像您要打开一个真正的关联，然后等待响应。 INIT-ACK块表示端口正在侦听（打开），而ABORT块表示非侦听器。如果在多次重新传输后未收到响应，则将端口标记为已过滤。如果收到ICMP不可达错误（类型3，代码0,1,2,3,9,10或13），则端口也会被标记为已过滤。
####SCTP COOKIE ECHO SCAN
SCTP COOKIE ECHO SCAN 是一种更先进的SCTP扫描。 它利用了SCTP实现应该在开放端口上静默丢弃包含COOKIE ECHO块的数据包这一事实，但如果端口关闭则发送ABORT。 这种扫描类型的优点是端口扫描不像INIT扫描那么明显。 此外，可能存在阻止INIT块的非状态防火墙规则集，但不阻止COOKIE ECHO块。 不要误以为这会使端口扫描不可见; 一个好的IDS也能够检测到SCTP COOKIE ECHO扫描。 缺点是SCTP COOKIE ECHO扫描不能区分打开和过滤的端口，在这两种情况下都会打开状态。

####IP Scan
IP协议扫描允许您确定目标计算机支持哪些IP协议（TCP，ICMP，IGMP等）。这在技术上不是端口扫描，因为它循环通过IP协议号而不是TCP或UDP端口号。然而，它仍然使用 -p 选项来选择扫描的协议号，以正常的端口表格式报告其结果，甚至使用与真正的端口扫描方法相同的底层扫描引擎。所以它足够接近它所属的端口扫描。

协议扫描的工作方式与UDP扫描类似。它不是遍历UDP数据包的端口号字段，而是发送IP数据包标头并迭代通过8位IP协议字段。标头通常是空的，不包含任何数据，甚至不包括所声明协议的正确标头。某些流行协议（包括TCP，UDP和ICMP）例外。包含适当的协议头，因为一些系统不会发送它们，因为Nmap已经具有创建它们的功能。协议扫描不是在观察ICMP端口不可达消息，而是在寻找ICMP协议不可达消息。如下表显示了对IP探测的响应如何映射到端口状态。
![image.png](https://upload-images.jianshu.io/upload_images/12067578-6ec2f49d960f680e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


与TCP或UDP协议中的开放端口一样，每个开放协议都是潜在的利用向量。此外，协议扫描结果有助于确定机器的用途以及采用何种类型的数据包过滤。终端主机通常只有TCP，UDP，ICMP和（有时）IGMP打开，而路由器通常提供更多，包括路由相关协议，如GRE和EGP。防火墙和VPN网关可能会显示与加密相关的协议，如IPsec和SWIPE。

与UDP扫描期间收到的ICMP端口不可达消息一样，ICMP协议不可达消息通常是速率限制的。例如，默认Linux 2.4.20框中每秒发送的ICMP目标无法访问响应不超过一个。由于只有256个可能的协议号，因此与65,536端口UDP扫描相比，这不是问题。

usage
协议扫描的使用方法与命令行上的大多数其他扫描技术的使用方法相同。除了一般的Nmap选项外，请简单指定 -sO 。普通端口 -p 选项用于选择协议号。或者，您可以使用 -F 扫描nmap-protocols数据库中列出的所有协议。默认情况下，Nmap扫描所有256个可能的值。
##### 目标端口选项
-p 端口、 -F 快速扫描、 -r 顺序扫描、 --top-ports<1~N> 扫描nmap-services中排名前N的端口

#####输出选项
-oN 正常输出、-oX 输出到XML文件中、-oG 淘汰的方式了
python-nmap库可以解析nmap输出的XML文件
还可以使用xsltproc进行格式转换，把XML抓换为HTML，xsltproc myscan.xml -o myscan.html

#####时间排程控制选项
Nmap可以通过 -T 选项来指定时间排程控制模式
- paranoid（0）：每5分钟发送一次数据包，且不会以并行的方式同时发送多组数据，这种模式不会被IDS检测到
- sneaky （1） ：每隔15秒发送一次数据包，且不会以并行方式同时发送多组数据。
- polite （2） ：每0.4秒发送一次数据包，且不会以并行的方式同时发送多组数据。
- normal （3） ： 此模式同时向多个目标发送多个数据包，为Nmap默认的模式，该模式能自动在扫描时间和网络负载之间进行平衡。
- aggressive （4） ：在这种模式下，Nmap对每个既定主机仅扫描75s，然后扫描下个主机。他等待响应的时间不超过0.3s

#####常用选项
服务版本识别：  -sV
eg： namp -sV xxx.xxx.xxx.xxx -p 32
操作系统检测： -O
禁用主机存活检测：有些主机可能屏蔽了ping请求，那么Nmap可能认为其没有开机，这将使得Nmap无法进行进一步检测，为了克服这一问题，可以使用 -Pn 参数
强力检测： -A    服务版本号、操作系统识别、脚本扫描、Traceroute   扫描时间比较长

##### 扫描ipv6主机 -6   
 eg： nmap -6 fe80:a00:27ff:xxx:xxxx

#####脚本引擎   Nmap使用的是Lua语言  -sC
eg：namp --script http-enum，http-headers，http-methods，http-php-version -p 80 1.2.3.4
![image.png](https://upload-images.jianshu.io/upload_images/12067578-7f563fa538f9e2bf.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
#####规避检测的选项
有时候目标会被放在IDS系统的保护之中，这时我们使用Nmap的默认模式，不仅会被发现，还会一无所获，
- -f （使用小数据包）：这个选项可以避免对方识别出我们探测的数据包。指定这个选项之后，Nmap将使用8字节甚至更小的数据体的数据包
- --mtu： 这个选项用来调整数据包的大小。MTU（Maximum Transmission Unit，最大传输单元）必须是8的整数倍，否则Nmap会报错
 - -D （诱饵）：这个选项应指定假IP，即诱饵的IP。启用这个选项之后，Nmap在发送侦测数据包的时候会掺杂一些源地址是假IP（诱饵）的数据包。这种功能意在以藏木与林的方式掩盖本机的真实IP。也就是说，对方的Log还好记录下本机的真实IP。你可以使用RND生成随机的假IP地址，或者用RND：number的参数生成<number>个假IP地址.你指定的诱饵IP应当在线，否则很容易击溃目标主机。另外，使用了过多的诱饵可能使得网络拥堵。尤其是在扫描客户的网络的时候。
-  --source-port <portnumber> 或 -g (模拟源端口): 如果防火墙只允许某些源端口的入站流量,这个选项就非常有用
- --data-length：这个选项用于改变Nmap发送数据包的默认数据长度，以避免被识别出来是Nmap的扫描数据
- --max-parallelism： 这个选项可以限制Nmap并发扫描的最大连接数。
- --scan-delay <time>: 这个选项用于控制发送探测数据的时间间隔,以避免达到IDS/IPS端口扫描规则的阀值
## Unicornscan
![image.png](https://upload-images.jianshu.io/upload_images/12067578-0282f9e8a8f957f9.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
加入我们要扫描主机1.2.3.4，检测它的UDP协议（-m U） 的1-65535端口，并查看程序的详尽输出（-Iv）， 那么我们需要使用下述命令：
unicornscan -m U -Iv 1.2.3.4:1-65535
我们在使用PPS默认值的情况下，这个扫描时间大约是30分钟，为了加快速度，我们可以把发包速度调整为1万
unicornscan -m U -Iv 1.2.3.4/24:1-65535 -r 10000 ，除非网络足够好，否则可能会造成网络瘫痪
##Zenmap
Zenmap 是图形的Nmap
##Amap 
可以检测指定端口上运行的应用程序信息。
 eg: amap -bq 1.2.3.4 22
 b：获取端口的banner信息，q：禁止程序报告关闭或不可识别的端口
可以用空格区分多个端口
#SNMB枚举（Simple Network Monitoring Protocol）
##onesixtyone
onesixtyone 1.2.3.4 如果要进行更细致的扫描可以启用-d选项
可以通过下面的方式安装snmp服务
```
apt-get install snmpd 
修改它的配置文件 /etc/default/snmpd
sudo vi /etc/default/snmpd
找到含有SNMPDOPTIONS 的那行，删掉本地地址127.0.0.1，然后重启SNMPD服务
sudo /etc/init.d/snmpd restart
```
##snmpcheck
snmpcheck -t 1.2.3.4
#VPN枚举
- 基于IPSec技术的VPN，需要复杂的安装配置采用这种方式连接入单位局域网的用户
- Open VPN， 需要VPN软件这种方案设置简单
- 基于SSL技术的VPN：只需要支持SSL连接的Web浏览器即可

###ike-scan
 是探测、识别并测试IPSec VPN的安全工具，


