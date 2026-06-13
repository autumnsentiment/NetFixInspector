# NetFixInspector 网络检测与修复工具

NetFixInspector 是一个 Windows/Linux 网络检测与保守修复工具。Windows 交付为原生 C++ `NetFixInspector.exe`，Linux 继续使用 `netfix-linux.sh + netfix.py`。

## Windows 使用

双击：

- `Run-NetFixInspector.bat` 或 `NetFixInspector.exe` 打开菜单

命令行：

```powershell
.\NetFixInspector.exe scan --skip-packet --no-external-inbound --output report.json
.\NetFixInspector.exe npcap --json
.\NetFixInspector.exe port --host example.com --port 443 --family both --count 3 --json
.\NetFixInspector.exe dhcp --active --timeout 5 --output dhcp.json
.\NetFixInspector.exe loop --seconds 15 --probes 5 --output loop.json
.\NetFixInspector.exe repair --interface "WLAN" --set-dns alidns
.\NetFixInspector.exe repair --interface "WLAN" --set-dns alidns --apply
```

## Npcap 集成

当前 exe 会运行时动态加载 Npcap：

- `C:\Windows\System32\Npcap\wpcap.dll`
- `C:\Windows\System32\wpcap.dll`
- 系统 DLL 搜索路径里的 `wpcap.dll`

安装 Npcap 后，DHCP 抓包、广播数统计、DHCP 源 IP/MAC、LAN 回路/广播风暴、ARP 冲突提示会自动启用。未安装 Npcap 时，普通连通性、DNS、NAT、IPv6、修复 dry-run 仍可用，DHCP 也会读取 Windows DHCP 状态并支持主动 Discover fallback。

注意：公开免费的 Npcap 安装器/驱动不应直接塞入第三方产品包再分发。若你有 Npcap OEM 授权安装器，请放到 `third_party\npcap` 或 `Install-Npcap.bat` 同目录，然后运行 `Install-Npcap.bat`。

## 一键脚本

- `Quick-Scan.bat`：快速检测
- `DNS-Check.bat`：DNS 检测
- `NAT-Check.bat`：NAT 检测
- `Port-Ping.bat`：TCP 端口 Ping，支持 IPv4/IPv6
- `DHCP-Check.bat`：DHCP 状态检测
- `DHCP-Active-Probe.bat`：DHCP 主动探测
- `DHCP-Packet-Capture.bat`：Npcap DHCP 抓包检测
- `Loop-Detect.bat`：Npcap LAN 回路/广播检测
- `Npcap-Status.bat`：Npcap 状态检测
- `Install-Npcap.bat`：本地/OEM Npcap 安装器安装；无本地安装器时打开官方下载页
- `Repair-DryRun.bat`：修复预演，不修改系统

## Linux 使用

```bash
python3 -m pip install -r requirements.txt
chmod +x ./netfix-linux.sh
./netfix-linux.sh scan --output report.json
./netfix-linux.sh port --host example.com --port 443 --family both --count 3 --json
sudo ./netfix-linux.sh scan --interface eth0 --dhcp-active --output report.json
```

## 状态含义

- `OK`：检测项正常或未发现明显问题
- `WARN`：发现风险、降级、权限不足或环境不完整
- `FAIL`：关键检测失败
- `SKIP`：检测项被跳过或缺少依赖
- `INFO`：信息或修复预演

默认所有修复都是 dry-run；只有加 `--apply` 才会修改系统。
