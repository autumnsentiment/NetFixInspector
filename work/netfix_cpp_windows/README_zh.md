# NetFixInspector Windows 原生 C++ 版

这是 NetFixInspector 的 Windows 10/11 x64 原生 C++ 控制台版。双击 `NetFixInspector.exe` 会打开交互菜单；也可以用命令行运行。Linux 版继续使用 `netfix-linux.sh + netfix.py`。

## 功能

- IPv4/IPv6 TCP 出站连通性检测
- TCP 端口 Ping：`port --host HOST --port PORT --family both|ipv4|ipv6 --count N`
- Windows 网卡、IPv4/IPv6 地址、MTU、默认路由、系统 DNS 读取
- UDP/53 直接 DNS A/AAAA 查询
- IPv4 NAT/STUN 映射检测
- IPv6 全局地址与出站检测
- DHCP 检测：
  - 无 Npcap 时读取 Windows DHCP 状态
  - `--active` 时发送 DHCP Discover 主动探测
  - 安装 Npcap 后自动抓包统计 DHCP 包、广播数、DHCP 源 IP/MAC
- LAN 回路/广播风暴检测：
  - 安装 Npcap 后抓取广播/组播/ARP
  - 输出 Top 源 MAC/IP、ARP 冲突提示、主动二层探测包回显
- 修复 dry-run 与 `--apply` 执行：flush DNS、Winsock/IP/IPv6 reset、DNS 替换

## Npcap 集成说明

本 exe 不再需要 Npcap SDK 重新编译；它会在运行时动态加载：

- `C:\Windows\System32\Npcap\wpcap.dll`
- `C:\Windows\System32\wpcap.dll`
- 系统 DLL 搜索路径中的 `wpcap.dll`

没有安装 Npcap 时，普通连通性、DNS、NAT、IPv6、修复 dry-run、DHCP fallback 仍可用；`loop` 和 DHCP 抓包部分会给出 WARN/SKIP。

注意：公开免费的 Npcap 安装器/驱动不应直接塞进第三方产品包再分发。若要随产品静默捆绑安装，请使用 Npcap OEM 授权安装器，并放到 `third_party\npcap` 或脚本同目录后运行 `Install-Npcap.bat`。

## 常用命令

```powershell
.\NetFixInspector.exe scan --skip-packet --no-external-inbound --output report.json
.\NetFixInspector.exe npcap --json
.\NetFixInspector.exe port --host example.com --port 443 --family both --count 3 --json
.\NetFixInspector.exe dns --provider cloudflare --json
.\NetFixInspector.exe nat --timeout 3 --json
.\NetFixInspector.exe dhcp --active --seconds 20 --output dhcp.json
.\NetFixInspector.exe loop --seconds 15 --probes 5 --output loop.json
.\NetFixInspector.exe repair --interface "WLAN 2" --set-dns alidns
.\NetFixInspector.exe repair --interface "WLAN 2" --set-dns alidns --apply
```

## 一键脚本

- `Run-NetFixInspector.bat`：打开交互菜单
- `Quick-Scan.bat`：快速检测
- `DNS-Check.bat`：DNS 检测
- `NAT-Check.bat`：NAT 检测
- `Port-Ping.bat`：TCP 端口 Ping，支持 IPv4/IPv6
- `DHCP-Check.bat`：DHCP 状态检测
- `DHCP-Active-Probe.bat`：DHCP 主动探测
- `DHCP-Packet-Capture.bat`：Npcap DHCP 抓包检测
- `Loop-Detect.bat`：Npcap LAN 回路/广播检测
- `Npcap-Status.bat`：Npcap 状态检测
- `Install-Npcap.bat`：使用本地/OEM 安装器安装；没有本地安装器时打开官方下载页
- `Repair-DryRun.bat`：修复预演，不修改系统

## 构建

便携 llvm-mingw：

```powershell
powershell -ExecutionPolicy Bypass -File .\build_windows_mingw.ps1
```

VS2022 + CMake：

```powershell
powershell -ExecutionPolicy Bypass -File .\build_windows_cpp.ps1
```

`-WithNpcap` 参数保留兼容旧命令，但现在 Npcap 是运行时动态加载，不需要 SDK 链接。
