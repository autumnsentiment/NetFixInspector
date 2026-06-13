# NetFixInspector

Windows/Linux 网络检测与保守修复工具。

## 当前交付

- Windows GUI：Electron 中文桌面版 `outputs/NetFixInspector-Electron/NetFixInspector.exe`
- Windows GUI 完整运行包：`outputs/NetFixInspector-Electron-With-FFmpeg.zip`，包含 Electron 运行库和 `ffmpeg.dll`
- Windows：原生 C++ 控制台程序 `outputs/NetFixInspector.exe`
- Windows 一键脚本：`outputs/*.bat`
- Linux：`outputs/netfix_tool/netfix-linux.sh + netfix.py`
- Windows C++ 源码：`work/netfix_cpp_windows`
- Windows Electron 源码：`work/netfix_electron`
- Linux/Python 参考实现：`work/netfix_tool`

## 主要功能

- IPv4/IPv6 网络连通性检测
- TCP 端口 Ping，支持 IPv4/IPv6 地址族选择
- DNS 读取、直连查询与可选替换
- IPv4 NAT/STUN 类型检测
- IPv6 地址、出站与可选入站检测
- DHCP 状态、主动 Discover、Npcap 抓包统计
- 内网回路、广播风暴、ARP 冲突提示
- Windows 网络修复 dry-run 与 `--apply`

## 快速使用

```powershell
cd outputs
.\Run-NetFixInspector-Electron.bat
.\Run-NetFixInspector.bat
.\NetFixInspector.exe scan --skip-packet --no-external-inbound --output report.json
.\NetFixInspector.exe port --host example.com --port 443 --family both --count 3 --json
.\NetFixInspector.exe dhcp --active --timeout 5 --output dhcp.json
.\NetFixInspector.exe loop --seconds 15 --probes 5 --output loop.json
```

Linux：

```bash
cd outputs/netfix_tool
chmod +x ./netfix-linux.sh
./netfix-linux.sh scan --output report.json
```

## Windows GUI 打包说明

Electron 桌面版依赖同目录运行库，请使用完整目录 `outputs/NetFixInspector-Electron\`，或下载 Release 中的 `NetFixInspector-Electron-With-FFmpeg.zip`。该压缩包已包含 `ffmpeg.dll`、Chromium/Electron 运行库、C++ 后端和 Npcap 安装入口。

## Npcap

Windows 抓包能力通过运行时动态加载 Npcap 启用。仓库不内置公开免费的 Npcap 驱动安装器；如需随产品分发，请使用 Npcap OEM 授权安装器，并放入 `work/netfix_electron/third_party/npcap/` 后重新构建 Electron 包。

## 许可证

本项目采用 MIT 风格的非商业许可证，详见 `LICENSE`。

禁止任何商业用途。标准 MIT License 本身允许商用，因此本项目的许可证不是标准 MIT/OSI 开源许可证；如需商业使用、商业分发、付费集成、托管服务或其他商业用途，请先取得作者书面授权。

## 说明

Windows App SDK/WinUI 封装已按当前要求移除；当前仓库保留 Electron 中文桌面版、C++ 控制台版、Linux 脚本版和打包产物。
