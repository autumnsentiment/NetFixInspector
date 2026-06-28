const actions = [
  { id: 'quick', title: '快速检测', desc: '基础网络、DNS、NAT、IPv6 摘要', options: { command: 'scan', quick: true } },
  { id: 'full', title: '完整检测', desc: '包含 DHCP 和内网回路检测', options: { command: 'scan', skipPacket: false } },
  { id: 'dns', title: 'DNS 检测', desc: '读取系统 DNS 并直连公共 DNS 查询', options: { command: 'dns' } },
  { id: 'nat', title: 'IPv4 NAT 类型', desc: '使用 STUN 判断公网映射行为', options: { command: 'nat' } },
  { id: 'ipv6', title: 'IPv6 检测', desc: '检测全局 IPv6、出站和可选入站', options: { command: 'ipv6' } },
  { id: 'port', title: '端口 Ping', desc: '填写地址和端口后再开始探测', options: { command: 'port' } },
  { id: 'dhcp', title: 'DHCP 检测', desc: '读取 DHCP 状态；有 Npcap 时抓包统计', options: { command: 'dhcp' } },
  { id: 'dhcp-active', title: 'DHCP 主动探测', desc: '发送 DHCP Discover，建议管理员运行', options: { command: 'dhcp', activeDhcp: true } },
  { id: 'loop', title: '内网回路检测', desc: '抓取广播/ARP 并进行二层探测', options: { command: 'loop' } },
  { id: 'npcap', title: 'Npcap 状态', desc: '检查抓包运行环境', options: { command: 'npcap' } },
  { id: 'repair-dry', title: '修复预演', desc: 'flush DNS、重置网络栈、DNS 替换预演', options: { command: 'repair' } },
  { id: 'repair-apply', title: '执行修复', desc: '会加 --apply，建议管理员运行', danger: true, options: { command: 'repair', apply: true } }
];

const commandNames = {
  scan: '网络扫描',
  connectivity: '连通性检测',
  dns: 'DNS 检测',
  nat: 'IPv4 NAT 类型检测',
  ipv6: 'IPv6 检测',
  port: '端口 Ping',
  dhcp: 'DHCP 检测',
  loop: '内网回路/广播检测',
  repair: '修复操作',
  npcap: 'Npcap 状态检测'
};

const checkNames = {
  'Interface inventory': '网卡与地址',
  'Default route': '默认路由',
  Connectivity: '网络连通性',
  'System DNS': '系统 DNS',
  DNS: 'DNS 解析',
  'IPv4 NAT': 'IPv4 NAT 类型',
  'IPv6 stack': 'IPv6 网络栈',
  'Port ping': '端口 Ping',
  'Packet-level LAN checks': '抓包级内网检测',
  'LAN health summary': '内网健康摘要',
  DHCP: 'DHCP 源检测',
  'LAN loop and broadcast storm': '内网回路/广播风暴',
  'Npcap runtime': 'Npcap 运行环境',
  Repair: '修复操作'
};

const statusNames = {
  OK: '正常',
  WARN: '警告',
  FAIL: '失败',
  SKIP: '跳过',
  INFO: '信息'
};

let lastReportPath = '';
let selectedAction = null;

const el = (id) => document.getElementById(id);

function readOptions(base) {
  return {
    ...base,
    timeout: Number(el('timeout').value || 3),
    seconds: Number(el('seconds').value || 15),
    probes: Number(el('probes').value || 5),
    portHost: el('portHost').value.trim(),
    port: Number(el('portNumber').value || 443),
    portCount: Number(el('portCount').value || 3),
    portFamily: el('portFamily').value,
    portProtocol: el('portProtocol').value,
    provider: el('provider').value,
    interfaceName: el('interfaceName').value,
    skipPacket: base.skipPacket ?? el('skipPacket').checked,
    noExternalInbound: el('noExternalInbound').checked
  };
}

function setRunning(running, text) {
  el('runState').textContent = text;
  document.querySelectorAll('.action, .secondary').forEach((button) => {
    button.classList.toggle('running', running);
    button.disabled = running;
  });
  el('startSelectedBtn').disabled = running || !selectedAction;
}

function statusClass(status) {
  return String(status || 'INFO').toLowerCase();
}

function localStatus(status) {
  return statusNames[status] || status || '信息';
}

function localCheck(name) {
  return checkNames[name] || name || '检测项';
}

function renderActions() {
  const container = el('actions');
  container.innerHTML = '';
  for (const action of actions) {
    const button = document.createElement('button');
    button.className = action.danger ? 'action danger' : 'action';
    button.dataset.actionId = action.id;
    button.innerHTML = `<strong>${action.title}</strong><span>${action.desc}</span>`;
    button.addEventListener('click', () => selectAction(action));
    container.appendChild(button);
  }
}

function selectAction(action) {
  selectedAction = action;
  const isPortPing = action.options?.command === 'port';
  document.querySelectorAll('.action').forEach((button) => {
    button.classList.toggle('selected', button.dataset.actionId === action.id);
  });
  el('portPingGroup').hidden = !isPortPing;
  el('selectedActionTitle').textContent = action.title;
  el('selectedActionDesc').textContent = action.desc;
  el('startSelectedBtn').textContent = action.danger ? `开始：${action.title}` : `开始 ${action.title}`;
  el('startSelectedBtn').disabled = false;
  el('runState').textContent = `已选择：${action.title}`;
  if (isPortPing) focusPortPing(false);
}

async function runAction(action) {
  if (action.options?.command === 'port' && !validatePortPing()) return;
  if (action.danger && !confirm('确认执行修复？这会修改系统设置。建议先运行“修复预演”。')) return;
  const options = readOptions(action.options);
  if (action.options.quick) options.skipPacket = true;
  setRunning(true, `正在执行：${action.title}`);
  el('checksPanel').innerHTML = '';
  el('jsonText').textContent = '{}';
  el('logText').textContent = '正在启动后端...';
  try {
    const result = await window.netfix.run(options);
    lastReportPath = result.outputPath;
    renderReport(result.report, result);
    el('jsonText').textContent = JSON.stringify(result.report, null, 2);
    el('logText').textContent = [
      `命令：${commandNames[options.command] || options.command}`,
      `参数：${result.args.join(' ')}`,
      `返回码：${result.code}`,
      `报告：${result.outputPath}`,
      '',
      result.stdout || '',
      result.stderr || ''
    ].join('\n');
    setRunning(false, `完成：${action.title}`);
  } catch (error) {
    el('checksPanel').innerHTML = '';
    el('checksPanel').appendChild(card('执行失败', 'FAIL', error.message || String(error), [], []));
    el('logText').textContent = error.stack || error.message || String(error);
    setRunning(false, '执行失败');
  }
}

function validatePortPing() {
  const host = el('portHost').value.trim();
  if (!host) {
    focusPortPing();
    el('runState').textContent = '请输入端口 Ping 的目标地址';
    return false;
  }
  return true;
}

function focusPortPing(markStatus = true) {
  const group = el('portPingGroup');
  group.hidden = false;
  group.classList.add('attention');
  group.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el('portHost').focus();
  if (markStatus) el('runState').textContent = '填写地址和端口后点击“开始 Ping”';
  setTimeout(() => group.classList.remove('attention'), 1400);
}

function renderReport(report, result) {
  const summaryStatus = report?.summary?.status || 'INFO';
  el('overallStatus').textContent = localStatus(summaryStatus);
  el('reportFile').textContent = result.outputPath || '-';
  el('adminState').textContent = report?.host?.admin ? '是' : '否';

  const panel = el('checksPanel');
  panel.innerHTML = '';
  panel.appendChild(card('总体状态', summaryStatus, `后端返回码：${result.code}`, [], []));
  if (report?.host) {
    panel.appendChild(card('主机信息', 'INFO', `主机：${report.host.hostname || '-'}\n系统：${report.host.platform || '-'}\n管理员权限：${report.host.admin ? '是' : '否'}`, [], []));
  }
  for (const check of report?.checks || []) {
    const actions = check.name === 'Npcap runtime'
      ? [{ label: '安装/修复 Npcap', handler: installNpcap }]
      : [];
    panel.appendChild(card(localCheck(check.name), check.status, check.summary, check.highlights, check.recommendations, actions));
  }
}

function card(title, status, summary, highlights = [], recommendations = [], actions = []) {
  const node = document.createElement('article');
  node.className = 'result-card';
  const highlightItems = (highlights || []).slice(0, 8).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  const recItems = (recommendations || []).slice(0, 6).map((item) => `<li>建议：${escapeHtml(item)}</li>`).join('');
  const actionItems = actions.map((action, index) => `<button class="secondary result-action" data-action-index="${index}">${escapeHtml(action.label)}</button>`).join('');
  node.innerHTML = `
    <div class="result-head">
      <h3>${escapeHtml(title)}</h3>
      <span class="badge ${statusClass(status)}">${escapeHtml(localStatus(status))}</span>
    </div>
    <div class="summary">${escapeHtml(summary || '-').replaceAll('\n', '<br>')}</div>
    ${highlightItems ? `<ul class="list">${highlightItems}</ul>` : ''}
    ${recItems ? `<ul class="list">${recItems}</ul>` : ''}
    ${actionItems ? `<div class="result-actions">${actionItems}</div>` : ''}
  `;
  node.querySelectorAll('[data-action-index]').forEach((button) => {
    button.addEventListener('click', () => actions[Number(button.dataset.actionIndex)]?.handler());
  });
  return node;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function wireTabs() {
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((item) => item.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach((item) => item.classList.remove('active'));
      tab.classList.add('active');
      el(`${tab.dataset.tab}Panel`).classList.add('active');
    });
  });
}

async function init() {
  renderActions();
  wireTabs();
  if (!window.netfix) {
    el('backendInfo').textContent = '当前不是 Electron 运行环境，请通过 NetFixInspector-Electron 启动。';
    setRunning(true, '后端不可用');
    return;
  }
  el('openReportBtn').addEventListener('click', () => lastReportPath && window.netfix.openPath(lastReportPath));
  el('openReportsBtn').addEventListener('click', () => window.netfix.openReports());
  el('adminBtn').addEventListener('click', () => window.netfix.restartElevated());
  el('startSelectedBtn').addEventListener('click', () => selectedAction && runAction(selectedAction));
  el('installNpcapBtn').addEventListener('click', installNpcap);
  el('installNpcapFooterBtn').addEventListener('click', installNpcap);
  try {
    const status = await window.netfix.backendStatus();
    el('backendInfo').textContent = `后端：${status.backendPath} · 报告目录：${status.reportDir}`;
    el('npcapBundleState').textContent = status.bundledNpcap ? '已内置' : '未内置';
    el('installNpcapBtn').textContent = status.bundledNpcap ? '安装内置 Npcap' : '安装/修复 Npcap';
    el('installNpcapFooterBtn').textContent = status.bundledNpcap ? '安装内置 Npcap' : '安装/修复 Npcap';
  } catch (error) {
    el('backendInfo').textContent = error.message || String(error);
    el('npcapBundleState').textContent = '未知';
  }
}

async function installNpcap() {
  const result = await window.netfix.installNpcap();
  if (result?.ok || result === true) {
    el('runState').textContent = result?.bundledNpcap ? '已打开内置 Npcap 安装器' : '已打开 Npcap 安装入口';
  }
}

init();
