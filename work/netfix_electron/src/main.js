const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn, spawnSync } = require('child_process');

const COMMANDS = new Set(['scan', 'connectivity', 'dns', 'nat', 'ipv6', 'dhcp', 'loop', 'repair', 'npcap', 'port', 'portping']);
const DNS_PROVIDERS = new Set(['cloudflare', 'alidns', 'google', 'tencent', 'quad9']);
const PORT_FAMILIES = new Set(['both', 'ipv4', 'ipv6']);
const PORT_PROTOCOLS = new Set(['tcp', 'udp']);

function logMainError(error, context = 'main') {
  try {
    const base = app.isReady() ? app.getPath('userData') : path.join(os.tmpdir(), 'NetFixInspector');
    fs.mkdirSync(base, { recursive: true });
    const text = [
      `[${new Date().toISOString()}] ${context}`,
      error?.stack || error?.message || String(error),
      ''
    ].join('\n');
    fs.appendFileSync(path.join(base, 'main-error.log'), text, 'utf8');
  } catch {
    // Best-effort crash logging only.
  }
}

process.on('uncaughtException', (error) => {
  logMainError(error, 'uncaughtException');
});

process.on('unhandledRejection', (error) => {
  logMainError(error, 'unhandledRejection');
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1220,
    height: 780,
    minWidth: 980,
    minHeight: 650,
    title: 'NetFixInspector 网络检测与修复',
    backgroundColor: '#f4f7fb',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

function backendPath() {
  const candidates = [
    path.join(process.resourcesPath || '', 'backend', 'NetFixInspector.exe'),
    path.join(app.getAppPath(), 'backend', 'NetFixInspector.exe'),
    path.join(__dirname, '..', 'backend', 'NetFixInspector.exe'),
    path.join(__dirname, '..', '..', '..', 'outputs', 'NetFixInspector.exe')
  ];
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) return candidate;
  }
  throw new Error('找不到 NetFixInspector.exe 后端，请确认 backend 目录存在。');
}

function supportRoots() {
  const roots = [
    path.join(process.resourcesPath || '', 'support'),
    app.isPackaged ? '' : path.join(app.getAppPath(), 'support'),
    path.join(__dirname, '..', 'support'),
    path.join(__dirname, '..', '..', '..', 'outputs')
  ].filter(Boolean);
  return [...new Set(roots.map((root) => path.normalize(root)))];
}

function supportPath(fileName) {
  for (const root of supportRoots()) {
    const candidate = path.join(root, fileName);
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(`找不到支持文件：${fileName}`);
}

function findBundledNpcapInstaller() {
  const roots = [];
  for (const root of supportRoots()) {
    roots.push(path.join(root, 'third_party', 'npcap'));
    roots.push(path.join(root, 'npcap'));
    roots.push(root);
  }
  const candidates = [];
  for (const root of roots) {
    try {
      if (!fs.existsSync(root)) continue;
      for (const name of fs.readdirSync(root)) {
        if (/^npcap.*\.exe$/i.test(name)) {
          const filePath = path.join(root, name);
          const stat = fs.statSync(filePath);
          if (stat.isFile()) candidates.push({ filePath, mtimeMs: stat.mtimeMs });
        }
      }
    } catch (error) {
      logMainError(error, `scan bundled npcap: ${root}`);
    }
  }
  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return candidates[0]?.filePath || '';
}

function reportDir() {
  const dir = path.join(app.getPath('userData'), 'reports');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function timestamp() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

function sanitizeOptions(options = {}) {
  const command = String(options.command || 'scan').toLowerCase();
  if (!COMMANDS.has(command)) throw new Error(`不支持的命令：${command}`);
  const timeout = Math.min(30, Math.max(1, Number(options.timeout || 3)));
  const seconds = Math.min(120, Math.max(1, Number(options.seconds || 15)));
  const probes = Math.min(50, Math.max(0, Number(options.probes || 5)));
  const port = Math.min(65535, Math.max(1, Number(options.port || 443)));
  const portCount = Math.min(20, Math.max(1, Number(options.portCount || 3)));
  const provider = String(options.provider || 'cloudflare').toLowerCase();
  const dnsProvider = DNS_PROVIDERS.has(provider) ? provider : 'cloudflare';
  const family = String(options.portFamily || 'both').toLowerCase();
  const protocol = String(options.portProtocol || 'tcp').toLowerCase();
  const iface = String(options.interfaceName || '').trim();
  return {
    command: command === 'portping' ? 'port' : command,
    timeout,
    seconds,
    probes,
    port,
    portCount,
    portHost: String(options.portHost || 'example.com').trim() || 'example.com',
    portFamily: PORT_FAMILIES.has(family) ? family : 'both',
    portProtocol: PORT_PROTOCOLS.has(protocol) ? protocol : 'tcp',
    provider: dnsProvider,
    interfaceName: iface,
    skipPacket: options.skipPacket !== false,
    noExternalInbound: options.noExternalInbound !== false,
    activeDhcp: Boolean(options.activeDhcp),
    apply: Boolean(options.apply),
    flushDns: options.flushDns !== false,
    resetStack: options.resetStack !== false
  };
}

function buildArgs(opts, outputPath) {
  const args = [opts.command, '--json', '--output', outputPath];
  if (opts.command !== 'loop') {
    args.push('--timeout', String(opts.timeout));
  }
  if (opts.command === 'scan') {
    if (opts.skipPacket) args.push('--skip-packet');
    if (opts.noExternalInbound) args.push('--no-external-inbound');
  }
  if (opts.command === 'dns') {
    args.push('--provider', opts.provider);
  }
  if (opts.command === 'ipv6' && opts.noExternalInbound) {
    args.push('--no-external-inbound');
  }
  if (opts.command === 'dhcp' && opts.activeDhcp) {
    args.push('--active');
  }
  if (opts.command === 'loop') {
    args.push('--seconds', String(opts.seconds), '--probes', String(opts.probes));
  }
  if (opts.command === 'port') {
    args.push('--host', opts.portHost, '--port', String(opts.port), '--family', opts.portFamily, '--count', String(opts.portCount), '--protocol', opts.portProtocol);
  }
  if (opts.command === 'repair') {
    if (opts.flushDns) args.push('--flush-dns');
    if (opts.resetStack) args.push('--reset-stack');
    args.push('--set-dns', opts.provider);
    if (opts.apply) args.push('--apply');
  }
  if (opts.interfaceName) {
    args.push('--interface', opts.interfaceName);
  }
  return args;
}

function parseReport(stdout, outputPath) {
  const trimmed = String(stdout || '').trim();
  const jsonText = trimmed.startsWith('{')
    ? trimmed
    : trimmed.includes('{')
      ? trimmed.slice(trimmed.indexOf('{'))
      : fs.existsSync(outputPath)
        ? fs.readFileSync(outputPath, 'utf8')
        : '';
  if (!jsonText) throw new Error('后端没有返回 JSON 报告。');
  return JSON.parse(jsonText);
}

ipcMain.handle('backend:run', async (_event, rawOptions) => {
  const opts = sanitizeOptions(rawOptions);
  const exe = backendPath();
  const outputPath = path.join(reportDir(), `NetFixInspector-${opts.command}-${timestamp()}.json`);
  const args = buildArgs(opts, outputPath);

  return await new Promise((resolve, reject) => {
    const child = spawn(exe, args, {
      windowsHide: true,
      cwd: path.dirname(exe),
      env: { ...process.env }
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      try {
        const report = parseReport(stdout, outputPath);
        resolve({ ok: true, code, report, outputPath, stdout, stderr, args });
      } catch (error) {
        reject(new Error(`${error.message}${stderr ? `\n${stderr}` : ''}`));
      }
    });
  });
});

ipcMain.handle('app:openPath', async (_event, targetPath) => {
  if (!targetPath || typeof targetPath !== 'string') return false;
  if (!fs.existsSync(targetPath)) return false;
  await shell.openPath(targetPath);
  return true;
});

ipcMain.handle('app:openReports', async () => {
  await shell.openPath(reportDir());
  return reportDir();
});

ipcMain.handle('app:backendStatus', async () => {
  const exe = backendPath();
  const version = spawnSync(exe, ['--help'], { encoding: 'utf8', windowsHide: true });
  const bundledNpcapInstaller = findBundledNpcapInstaller();
  return {
    backendPath: exe,
    reportDir: reportDir(),
    platform: `${os.type()} ${os.release()}`,
    helpOk: version.status === 0,
    bundledNpcapInstaller,
    bundledNpcap: Boolean(bundledNpcapInstaller)
  };
});

ipcMain.handle('app:installNpcap', async () => {
  const script = supportPath('Install-Npcap.ps1');
  const bundledNpcapInstaller = findBundledNpcapInstaller();
  const installArgs = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script];
  if (bundledNpcapInstaller) {
    installArgs.push('-InstallerPath', bundledNpcapInstaller);
  }
  const result = spawnSync('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-Command',
    `Start-Process -FilePath powershell.exe -ArgumentList @(${installArgs.map((arg) => JSON.stringify(arg)).join(',')}) -Verb RunAs`
  ], { windowsHide: true, encoding: 'utf8' });
  if (result.status === 0) {
    return { ok: true, bundledNpcap: Boolean(bundledNpcapInstaller), installerPath: bundledNpcapInstaller };
  }
  dialog.showErrorBox('Npcap 安装入口启动失败', result.stderr || '用户可能取消了 UAC。');
  return { ok: false, bundledNpcap: Boolean(bundledNpcapInstaller), installerPath: bundledNpcapInstaller };
});

ipcMain.handle('app:restartElevated', async () => {
  const exe = process.execPath;
  const result = spawnSync('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-Command',
    `Start-Process -FilePath ${JSON.stringify(exe)} -Verb RunAs`
  ], { windowsHide: true, encoding: 'utf8' });
  if (result.status === 0) {
    app.quit();
    return true;
  }
  dialog.showErrorBox('管理员启动失败', result.stderr || '用户可能取消了 UAC。');
  return false;
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
}).catch((error) => {
  logMainError(error, 'app.whenReady');
  dialog.showErrorBox('NetFixInspector 启动失败', error?.message || String(error));
  app.exit(1);
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
