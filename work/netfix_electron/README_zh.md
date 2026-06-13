# NetFixInspector Electron 中文封装

这是 NetFixInspector 的 Electron 中文桌面封装。Electron 只负责界面、参数选择、报告展示和打开文件；实际网络检测仍由原生 C++ 后端 `NetFixInspector.exe` 执行。

## 功能入口

- 快速检测、完整检测
- DNS 检测、IPv4 NAT 类型、IPv6 检测
- 端口 Ping：TCP 连接探测，支持 IPv4/IPv6
- DHCP 检测、DHCP 主动探测
- 内网回路检测、Npcap 状态
- 修复预演、执行修复

## 构建

```powershell
powershell -ExecutionPolicy Bypass -File .\build_electron.ps1
```

构建产物会复制到：

```text
outputs\NetFixInspector-Electron\
```

Release 额外提供 `NetFixInspector-Electron-With-FFmpeg.zip`，包含完整 Electron 运行目录、`ffmpeg.dll`、C++ 后端和支持脚本。桌面版不要只拷贝单个 `NetFixInspector.exe` 到其他目录运行。

## 后端

构建脚本会把 `outputs\NetFixInspector.exe` 复制到 `backend\NetFixInspector.exe`，Electron 打包后会从 `resources\backend\NetFixInspector.exe` 加载它。

## Npcap

本封装支持内置授权的 Npcap OEM 安装器。把授权安装器放到：

```text
work\netfix_electron\third_party\npcap\npcap-oem.exe
```

然后重新运行 `build_electron.ps1`，安装器会被打进：

```text
NetFixInspector-Electron\resources\support\third_party\npcap\
```

桌面界面会显示“Npcap 安装器：已内置”，点击“安装内置 Npcap”时优先运行包内安装器。若未放入授权安装器，按钮会打开 Npcap 官方下载页。

不要把公开免费的 Npcap 安装器/驱动直接塞入第三方发布包，除非你的 Npcap 授权允许这样分发。后端会运行时动态检测 Npcap；未安装时 DHCP 抓包和内网回路抓包检测会降级或提示跳过，其他检测照常可用。

## 许可证

本项目采用 MIT 风格的非商业许可证，详见 `LICENSE` 或仓库根目录 `LICENSE`。

禁止任何商业用途。标准 MIT License 本身允许商用，因此本项目的许可证不是标准 MIT/OSI 开源许可证；如需商业使用、商业分发、付费集成、托管服务或其他商业用途，请先取得作者书面授权。
