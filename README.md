# 简单端口扫描检测器

这里分两个部分来编写，一个是检测工具 （portscan_simple.c），一个是ebpf的加载程序（loader_simple.c）

先分别解释这两个文件的编写思路：

## ebpf程序



挂到网卡的 XDP hook 上，实时检查进入接口的包：

识别 TCP SYN（ACK=0）探测包（端口扫描的包）

**当30秒同一个ip对超过24 个不同的端口进行端口扫描进行阻断（drop丢弃该包），并产生日志写入map**

## loader程序

用 **libbpf** 打开/加载 **portscan_simple.o** （portscan_simple.c编译结果）到内核

把 XDP 程序附加到接口（native 失败则 fallback xdpgeneric）

读取map里的告警日志并输出

## 效果

<img width="622" height="118" alt="image" src="https://github.com/user-attachments/assets/1f09c133-2703-4a44-a4d0-a938f3bcac7c" />


<img width="708" height="414" alt="image" src="https://github.com/user-attachments/assets/d31471cf-7e44-413b-8d53-dc7a54f60a76" />




## 如何使用

git clone https://github.com/putaom0l1/ebpf_xdp_prevent_portscan.git

make

./loader_simple ens33
