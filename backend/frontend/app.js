/* QEMU Session Guard WebUI — 无构建依赖的原生 ES 前端 */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const OPS = ["read", "power", "console", "config"];
const POWER_ACTIONS = ["start", "shutdown", "stop", "resume", "force_off"];

const state = {
  vms: [], volumes: [], sessions: [], approvals: [],
  statuses: {}, discovered: [], editingSession: null,
};

/* ------------------------------- API 封装 ------------------------------- */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let msg = `${res.status}`;
    try { msg = (await res.json()).error || (await res.json()).detail || msg; } catch { try { msg = await res.text() || msg; } catch { /* ignore */ } }
    throw new Error(msg);
  }
  return res.json();
}

function toast(msg, isErr = false) {
  const el = document.createElement("div");
  el.className = "alert " + (isErr ? "warn" : "info");
  el.textContent = msg;
  el.style.position = "fixed"; el.style.top = "14px"; el.style.right = "14px";
  el.style.zIndex = 99; el.style.maxWidth = "420px";
  document.body.appendChild(el);
  setTimeout(() => el.remove(), isErr ? 6000 : 3000);
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false }) : "-";
const statusTag = (s) => `<span class="tag ${esc(s)}">${esc(s)}</span>`;
const resultTag = (r) => `<span class="tag ${esc(r)}">${esc(r)}</span>`;

/* ------------------------------- 视图切换 ------------------------------- */
$$("nav button").forEach((btn) => btn.addEventListener("click", () => {
  $$("nav button").forEach((b) => b.classList.remove("active"));
  $$(".view").forEach((v) => v.classList.remove("active"));
  btn.classList.add("active");
  $("#view-" + btn.dataset.view).classList.add("active");
  refreshAll();
}));

/* ------------------------------- VM 注册 ------------------------------- */
async function loadVms() {
  const { vms } = await api("/api/vms");
  state.vms = vms;
  const tb = $("#vmTable tbody");
  tb.innerHTML = vms.map((vm) => {
    const visibleIn = state.sessions.filter((s) => (s.perms?.granted_vm_ids || []).includes(vm.id)).length;
    return `<tr>
      <td class="mono">${esc(vm.id)}</td><td>${esc(vm.arch)}</td>
      <td>${esc(vm.qemu_version)}</td><td>${esc(vm.qemu_variant)}</td>
      <td>${vm.resources.vcpus}C / ${vm.resources.mem_mb}MB</td>
      <td>${statusTag(state.statuses[vm.id] || vm.status || "stopped")}</td>
      <td class="muted">${visibleIn} 个会话可见</td>
      <td>${POWER_ACTIONS.map((a) => `<button class="btn ${a === "force_off" ? "danger" : ""}" onclick="vmPower('${esc(vm.id)}','${a}')">${a}</button>`).join(" ")}
          <button class="btn danger" onclick="vmDelete('${esc(vm.id)}')">删除</button></td>
    </tr>`;
  }).join("") || `<tr><td colspan="8" class="muted">尚未注册 VM</td></tr>`;
  renderMatrix($("#permMatrix"), vms, {});
  if (state.editingSession) renderMatrix($("#editMatrix"), vms, state.editingSession.perms);
}

window.vmPower = async (id, action) => {
  if (action === "force_off" && !confirm(`确认强制断电 ${id}？`)) return;
  try { await api(`/api/vms/${id}/power/${action}`, { method: "POST" }); toast(`${action} 已下发`); }
  catch (e) { toast(e.message, true); }
};

window.vmDelete = async (id) => {
  if (!confirm(`删除 VM 注册 ${id}？（不影响已存在的磁盘文件）`)) return;
  try { await api(`/api/vms/${id}`, { method: "DELETE" }); await refreshAll(); }
  catch (e) { toast(e.message, true); }
};

$("#btnDiscover").addEventListener("click", async () => {
  const box = $("#discoverResult");
  box.textContent = "探测中…";
  try {
    const { candidates } = await api("/api/qemu/discover");
    state.discovered = candidates;
    $("#vmBinary").innerHTML = candidates.map((c) =>
      `<option value="${esc(c.path)}">${esc(c.path)}  [${esc(c.variant)} ${esc(c.version)}]</option>`).join("");
    box.textContent = candidates.length
      ? `发现 ${candidates.length} 个可用 QEMU：${candidates.map((c) => c.variant).join(", ")}`
      : "未发现 QEMU。请确认 MSYS2 已安装（pacman -S mingw-w64-ucrt-x86_64-qemu）或设置 QEMU_BINARY_DIR / MSYS2_ROOT。";
  } catch (e) { box.textContent = "发现失败: " + e.message; }
});

$("#btnRegVm").addEventListener("click", async () => {
  const extra = $("#vmExtra").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const body = {
    id: $("#vmId").value.trim(),
    arch: $("#vmArch").value,
    qemu_binary: $("#vmBinary").value,
    vcpus: +$("#vmVcpus").value || 2,
    mem_mb: +$("#vmMem").value || 2048,
    disk_volume_ids: [...$("#vmVolumes").selectedOptions].map((o) => o.value),
    extra_args: extra,
  };
  if (!body.id || !body.qemu_binary) return toast("请先发现 QEMU 并填写 VM ID", true);
  try { await api("/api/vms", { method: "POST", body }); toast("VM 已注册"); await refreshAll(); }
  catch (e) { toast(e.message, true); }
});

/* ------------------------------- 卷 ------------------------------- */
async function loadVolumes() {
  const { volumes } = await api("/api/volumes");
  state.volumes = volumes;
  $("#volTable tbody").innerHTML = volumes.map((v) =>
    `<tr><td class="mono">${esc(v.id)}</td><td class="mono">${esc(v.path)}</td><td>${v.read_only ? "✔" : "✘"}</td>
     <td><button class="btn danger" onclick="volDelete('${esc(v.id)}')">删除</button></td></tr>`).join("")
    || `<tr><td colspan="4" class="muted">无预注册卷</td></tr>`;
  $("#vmVolumes").innerHTML = volumes.map((v) => `<option value="${esc(v.id)}">${esc(v.id)} (${v.read_only ? "RO" : "RW"})</option>`).join("");
}

window.volDelete = async (id) => {
  try { await api(`/api/volumes/${id}`, { method: "DELETE" }); await loadVolumes(); }
  catch (e) { toast(e.message, true); }
};

$("#btnAddVol").addEventListener("click", async () => {
  const body = { id: $("#volId").value.trim(), path: $("#volPath").value.trim(), read_only: $("#volRo").checked };
  if (!body.id || !body.path) return toast("卷 ID 与路径必填", true);
  try { await api("/api/volumes", { method: "POST", body }); await loadVolumes(); }
  catch (e) { toast(e.message, true); }
});

/* ------------------------------- 权限矩阵 ------------------------------- */
function renderMatrix(container, vms, perms) {
  if (!container) return;
  const pmap = perms?.permission_map || {};
  const granted = new Set(perms?.granted_vm_ids || vms.map((v) => v.id));
  const rows = vms.map((vm) => {
    const cur = new Set(pmap[vm.id] || []);
    const vis = granted.size === 0 ? true : granted.has(vm.id);
    return `<tr><td class="mono">${esc(vm.id)}</td>${OPS.map((op) =>
      `<td style="text-align:center"><input type="checkbox" data-vm="${esc(vm.id)}" data-op="${op}"
        ${cur.has(op) || (Object.keys(pmap).length === 0 && vis && op === "read") ? "checked" : ""}></td>`).join("")}
      <td><button class="btn" onclick="matrixRow(this,'${esc(vm.id)}',true)">全选</button>
          <button class="btn" onclick="matrixRow(this,'${esc(vm.id)}',false)">清空</button></td></tr>`;
  }).join("");
  container.innerHTML = `<table class="matrix"><thead><tr><th>VM</th>${OPS.map((o) => `<th class="op" style="text-align:center">${o}</th>`).join("")}<th>批量</th></tr></thead><tbody>${rows || `<tr><td colspan="6" class="muted">先注册 VM</td></tr>`}</tbody></table>`;
}

window.matrixRow = (btn, vmId, on) => {
  btn.closest("tr").querySelectorAll(`input[data-vm="${CSS.escape(vmId)}"]`).forEach((cb) => { cb.checked = on; });
};

function readMatrix(container) {
  const granted = [], permission_map = {};
  container.querySelectorAll("input[type=checkbox][data-vm]").forEach((cb) => {
    const vm = cb.dataset.vm, op = cb.dataset.op;
    if (!cb.checked) return;
    if (!granted.includes(vm)) granted.push(vm);
    (permission_map[vm] ||= []).push(op);
  });
  // read 是其余权限的前提：补全
  for (const vm of Object.keys(permission_map)) {
    if (!permission_map[vm].includes("read")) permission_map[vm].unshift("read");
  }
  return { granted_vm_ids: granted, permission_map };
}

/* ------------------------------- 会话 ------------------------------- */
async function loadSessions() {
  const { sessions } = await api("/api/sessions");
  state.sessions = sessions;
  $("#sessTable tbody").innerHTML = sessions.map((s) => {
    const active = s.active && !s.expired;
    return `<tr>
      <td class="mono" title="${esc(s.id)}">${esc(s.id.slice(0, 8))}…</td>
      <td>${esc(s.label || "-")} <span class="muted">/ ${esc(s.owner)}</span></td>
      <td>${s.perms.granted_vm_ids.length} 台</td>
      <td class="muted">${s.perms.quota.max_running_vms} 运行 / ${s.perms.quota.max_vcpus_per_vm}C / ${s.perms.quota.max_mem_mb_per_vm}MB</td>
      <td>g${s.perms_generation}</td>
      <td class="muted">${fmtTime(s.last_activity_at)}</td>
      <td>${active ? '<span class="tag running">active</span>' : '<span class="tag stopped">inactive</span>'}</td>
      <td><button class="btn" onclick="editSession('${esc(s.id)}')">权限 / 详情</button></td>
    </tr>`;
  }).join("") || `<tr><td colspan="8" class="muted">无会话</td></tr>`;
}

$("#btnCreateSess").addEventListener("click", async () => {
  const { granted_vm_ids, permission_map } = readMatrix($("#permMatrix"));
  const approval_actions = [...$("#sessApproval").selectedOptions].map((o) => o.value);
  const body = {
    label: $("#sessLabel").value.trim(), owner: $("#sessOwner").value.trim() || "admin",
    granted_vm_ids, permission_map, approval_actions,
    quota: {
      max_running_vms: +$("#qMaxRun").value || 0,
      max_vcpus_per_vm: +$("#qMaxCpu").value || 1,
      max_mem_mb_per_vm: +$("#qMaxMem").value || 128,
    },
  };
  if (!granted_vm_ids.length) return toast("请至少在权限矩阵中勾选一个权限", true);
  try {
    const s = await api("/api/sessions", { method: "POST", body });
    toast(`会话已创建：${s.id}`);
    await refreshAll();
  } catch (e) { toast(e.message, true); }
});

window.editSession = async (id) => {
  const s = await api(`/api/sessions/${id}`);
  state.editingSession = s;
  $("#sessDetail").style.display = "block";
  $("#sessDetailId").textContent = s.id;
  renderMatrix($("#editMatrix"), state.vms, s.perms);
  const { audits } = await api(`/api/audits?session_id=${encodeURIComponent(id)}&limit=50`);
  $("#sessAuditTable tbody").innerHTML = audits.map((e) =>
    `<tr><td class="muted">${fmtTime(e.ts)}</td><td>${esc(e.action)}</td><td class="mono">${esc(e.vm_id || "")}</td>
     <td>${resultTag(e.result)}</td><td class="muted">${esc(e.deny_reason)}</td></tr>`).join("")
    || `<tr><td colspan="5" class="muted">无记录</td></tr>`;
  $("#sessDetail").scrollIntoView({ behavior: "smooth" });
};

$("#btnSavePerms").addEventListener("click", async () => {
  const s = state.editingSession;
  if (!s) return;
  const { granted_vm_ids, permission_map } = readMatrix($("#editMatrix"));
  if (!confirm("权限变更将生成新快照，仅对后续 tool 调用生效。继续？")) return;
  try {
    const r = await api(`/api/sessions/${s.id}/perms`, { method: "PUT", body: { granted_vm_ids, permission_map } });
    toast(r.note);
    state.editingSession = r.session;
    await loadSessions();
  } catch (e) { toast(e.message, true); }
});

$("#btnDeactivate").addEventListener("click", async () => {
  const s = state.editingSession;
  if (!s || !confirm(`停用会话 ${s.id}？其所有后续 tool 调用将被拒绝。`)) return;
  await api(`/api/sessions/${s.id}/deactivate`, { method: "POST" });
  $("#sessDetail").style.display = "none";
  state.editingSession = null;
  await loadSessions();
});

$("#btnCloseDetail").addEventListener("click", () => {
  $("#sessDetail").style.display = "none";
  state.editingSession = null;
});

/* ------------------------------- 审批 ------------------------------- */
async function loadApprovals() {
  const { approvals } = await api("/api/approvals");
  state.approvals = approvals;
  const pending = approvals.filter((a) => a.status === "pending");
  const badge = $("#apprBadge");
  badge.style.display = pending.length ? "inline-block" : "none";
  badge.textContent = pending.length;
  $("#apprTable tbody").innerHTML = pending.map((a) =>
    `<tr><td class="muted">${fmtTime(a.created_at)}</td><td class="mono" title="${esc(a.session_id)}">${esc(a.session_id.slice(0, 8))}…</td>
     <td>${esc(a.action)}</td><td class="mono">${esc(a.vm_id)}</td>
     <td class="mono muted">${esc(JSON.stringify(a.params))}</td>
     <td class="muted">${fmtTime(a.expires_at)}</td>
     <td><button class="btn primary" onclick="decide('${esc(a.id)}',true)">批准</button>
         <button class="btn danger" onclick="decide('${esc(a.id)}',false)">拒绝</button></td></tr>`).join("")
    || `<tr><td colspan="7" class="muted">无待审批操作</td></tr>`;
  $("#apprHistTable tbody").innerHTML = approvals.filter((a) => a.status !== "pending").slice(0, 50).map((a) =>
    `<tr><td class="muted">${fmtTime(a.decided_at || a.created_at)}</td><td class="mono">${esc(a.session_id.slice(0, 8))}…</td>
     <td>${esc(a.action)}</td><td class="mono">${esc(a.vm_id)}</td>
     <td>${resultTag(a.status === "approved" ? "allowed" : "denied")} ${esc(a.status)}</td>
     <td>${esc(a.decided_by || "-")}</td></tr>`).join("")
    || `<tr><td colspan="6" class="muted">无历史审批</td></tr>`;
}

window.decide = async (id, approve) => {
  try { await api(`/api/approvals/${id}/decide`, { method: "POST", body: { approve, decided_by: "admin" } }); }
  catch (e) { toast(e.message, true); }
  await loadApprovals();
};

/* ------------------------------- 审计 ------------------------------- */
async function loadAudits() {
  const q = new URLSearchParams();
  if ($("#fltResult").value) q.set("result", $("#fltResult").value);
  if ($("#fltSession").value) q.set("session_id", $("#fltSession").value.trim());
  if ($("#fltVm").value) q.set("vm_id", $("#fltVm").value.trim());
  q.set("limit", "300");
  const { audits } = await api("/api/audits?" + q);
  $("#auditTable tbody").innerHTML = audits.map((e) =>
    `<tr><td class="muted mono">${fmtTime(e.ts)}</td>
     <td class="mono" title="${esc(e.session_id)}">${esc((e.session_label || e.session_id || "").slice(0, 12))}</td>
     <td>${esc(e.action)}</td><td class="mono">${esc(e.vm_id || "")}</td>
     <td>${resultTag(e.result)}</td><td class="muted">${esc(e.deny_reason)}</td>
     <td><details><summary>详情</summary><pre>${esc(JSON.stringify({ params: e.model_params, executed: e.executed, approval_id: e.approval_id, error: e.error, actor: e.actor }, null, 2))}</pre></details></td></tr>`).join("")
    || `<tr><td colspan="7" class="muted">无记录</td></tr>`;
}

$("#btnFlt").addEventListener("click", loadAudits);
$("#btnExport").addEventListener("click", () => {
  const q = new URLSearchParams();
  if ($("#fltResult").value) q.set("result", $("#fltResult").value);
  if ($("#fltSession").value) q.set("session_id", $("#fltSession").value.trim());
  if ($("#fltVm").value) q.set("vm_id", $("#fltVm").value.trim());
  q.set("format", "csv"); q.set("limit", "2000");
  window.open("/api/audits?" + q, "_blank");
});

/* ------------------------------- 监控 ------------------------------- */
function renderMonitor() {
  const vms = state.vms;
  $("#kpiVms").textContent = vms.length;
  $("#kpiRunning").textContent = Object.values(state.statuses).filter((s) => ["running", "paused", "starting"].includes(s)).length;
  $("#kpiSessions").textContent = state.sessions.filter((s) => s.active).length;
  $("#kpiPending").textContent = state.approvals.filter((a) => a.status === "pending").length;
  $("#monTable tbody").innerHTML = vms.map((vm) => {
    const st = state.statuses[vm.id] || "stopped";
    return `<tr><td class="mono">${esc(vm.id)}</td><td>${statusTag(st)}</td><td class="mono" id="pid-${esc(vm.id)}">-</td>
      <td>-</td><td>-</td><td class="muted">${new Date().toLocaleTimeString("zh-CN", { hour12: false })}</td></tr>`;
  }).join("") || `<tr><td colspan="6" class="muted">无 VM</td></tr>`;
}

function logEvent(msg) {
  const el = $("#eventLog");
  const line = `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] ${msg.type} ${JSON.stringify(msg).slice(0, 300)}\n`;
  el.textContent = line + el.textContent;
  if (el.textContent.length > 20000) el.textContent = el.textContent.slice(0, 20000);
}

/* ------------------------------- WebSocket ------------------------------- */
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  const wsState = $("#wsState");
  ws.onopen = () => { wsState.textContent = "WebSocket: 已连接"; wsState.classList.add("on"); };
  ws.onclose = () => {
    wsState.textContent = "WebSocket: 断开，3s 后重连"; wsState.classList.remove("on");
    setTimeout(connectWs, 3000);
  };
  ws.onmessage = (ev) => {
    let msg; try { msg = JSON.parse(ev.data); } catch { return; }
    logEvent(msg);
    if (msg.type === "snapshot") { state.statuses = msg.statuses || {}; }
    if (msg.type === "vm.status") { state.statuses[msg.vm_id] = msg.status; }
    if (msg.type === "vm.exited") { state.statuses[msg.vm_id] = "shutdown"; }
    if (msg.type === "approval.requested" || msg.type === "approval.decided") { loadApprovals(); }
    if (msg.type === "security.probe_alert") { toast("⚠️ " + msg.message, true); }
    renderMonitor();
    if ($("#view-vms").classList.contains("active")) loadVms();
  };
}

/* ------------------------------- 启动 ------------------------------- */
async function refreshAll() {
  try {
    const { statuses } = await api("/api/status");
    state.statuses = statuses;
  } catch { /* 后端未就绪 */ }
  await Promise.allSettled([loadVolumes(), loadSessions(), loadApprovals(), loadAudits()]);
  await loadVms();
  renderMonitor();
}

refreshAll();
connectWs();
setInterval(async () => {  // 状态轮询兜底（WebSocket 之外）
  try { const { statuses } = await api("/api/status"); state.statuses = statuses; renderMonitor(); } catch { /* ignore */ }
}, 5000);
