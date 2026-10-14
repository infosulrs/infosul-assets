"use strict";
// INFOSUL Scanner: interface. Todo texto vindo da rede passa por esc().

const TOKEN = new URLSearchParams(location.search).get("t") || "";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = {
  info: null, results: new Map(), order: [], count: 0, running: false,
  tab: "results", sel: null, sort: { key: "ip", asc: true }, polling: false,
};

async function api(path, body) {
  const opt = { headers: { "X-Token": TOKEN } };
  if (body !== undefined) {
    opt.method = "POST";
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function toast(msg, err) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (err ? " err" : "");
  t.hidden = false;
  clearTimeout(toast.h);
  toast.h = setTimeout(() => (t.hidden = true), err ? 6000 : 3000);
}

const ipKey = (ip) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
const macKey = (r) => (r.mac || "").toUpperCase();

/* ---------- carregamento ---------- */
async function loadInfo() {
  state.info = await api("/api/info");
  $("#aVersion").textContent = "v" + state.info.version;
  const dl = $("#mru");
  dl.innerHTML = (state.info.mru || []).map((m) => `<option value="${esc(m)}">`).join("");
  if (!$("#range").value) {
    const net = (state.info.networks || [])[0];
    $("#range").value = (state.info.mru || [])[0] || (net ? net.range : "");
  }
  $("#cntFav").textContent = (state.info.favorites || []).length;
}

/* ---------- verificação ---------- */
async function startScan() {
  if (state.running) {
    await api("/api/stop", {});
    return;
  }
  const range = $("#range").value.trim();
  if (!range) return toast("Informe a faixa de IPs a verificar.", true);
  try {
    await api("/api/scan", { range });
  } catch (e) {
    return toast(e.message, true);
  }
  state.results.clear();
  state.order = [];
  state.count = 0;
  state.sel = null;
  renderDetails();
  setRunning(true);
  if (state.tab !== "results") switchTab("results");
  poll();
}

function setRunning(on) {
  state.running = on;
  $("#scanLabel").textContent = on ? "Parar" : "Verificar";
  $("#btnScan .ico").innerHTML = on ? "&#9632;" : "&#9654;";
  $("#btnScan").classList.toggle("stop", on);
}

async function poll() {
  if (state.polling) return;
  state.polling = true;
  try {
    for (;;) {
      const s = await api("/api/state?since=" + state.count);
      for (const r of s.results) {
        state.results.set(r.ip, r);
        state.order.push(r.ip);
      }
      state.count = s.count;
      updateStatus(s.progress);
      if (s.results.length) render();
      if (!s.progress.running) {
        setRunning(false);
        render();
        loadInfo();
        break;
      }
      await new Promise((r) => setTimeout(r, 450));
    }
  } catch (e) {
    toast(e.message, true);
    setRunning(false);
  } finally {
    state.polling = false;
  }
}

function updateStatus(p) {
  const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
  $("#barFill").style.width = pct + "%";
  const secs = (p.elapsedMs / 1000).toFixed(1);
  const base = `${p.alive} ativos, ${p.dead} inativos, ${p.unknown} desconhecidos`;
  $("#statusText").textContent = p.running
    ? `Verificação... ${pct}% (${p.done}/${p.total}), ${base}`
    : p.total
      ? `${p.canceled ? "Verificação interrompida" : "Concluído"} em ${secs} s: ${base}`
      : "Pronto";
}

/* ---------- tabela ---------- */
function currentRows() {
  const q = $("#search").value.trim().toLowerCase();
  let rows;
  if (state.tab === "favorites") {
    rows = (state.info?.favorites || []).map((f) => {
      const live = state.results.get(f.ip);
      const base = live && (!f.mac || macKey(live) === f.mac.toUpperCase()) ? live : { ip: f.ip, mac: f.mac, status: "desconhecido", services: [] };
      return { ...base, name: f.name || base.name, comment: f.comment || base.comment, favorite: true, mac: base.mac || f.mac };
    });
  } else {
    const alive = $("#fAlive").checked, dead = $("#fDead").checked;
    rows = state.order.map((ip) => state.results.get(ip)).filter((r) => (r.status === "ativo" ? alive : dead));
  }
  if (q) {
    rows = rows.filter((r) =>
      [r.name, r.ip, r.mac, r.vendor, r.type, r.comment, r.netbiosName, r.user, ...(r.services || []).map((s) => s.name + " " + s.detail)]
        .join(" ").toLowerCase().includes(q));
  }
  const { key, asc } = state.sort;
  const val = (r) => (key === "ip" ? ipKey(r.ip) : String(r[key] ?? "").toLowerCase());
  rows.sort((a, b) => {
    const x = val(a), y = val(b);
    return (x < y ? -1 : x > y ? 1 : 0) * (asc ? 1 : -1);
  });
  return rows;
}

const ACT = { http: "http", http8080: "http", https: "https", ftp: "ftp", rdp: "rdp", ssh: "ssh", telnet: "telnet", smb: "explore", winbox: "winbox" };

function chips(r) {
  return (r.services || []).map((s) => {
    const a = ACT[s.key];
    return `<span class="chip${a ? " act" : ""}" ${a ? `data-act="${a}" data-port="${s.port}"` : ""} title="${esc(s.name + ":" + s.port + (s.detail ? " " + s.detail : ""))}">${esc(s.name)}</span>`;
  }).join("") + ((r.shares || []).length ? `<span class="chip act" data-act="explore" title="Pastas compartilhadas">${r.shares.length} compart.</span>` : "");
}

function render() {
  const rows = currentRows();
  $("#cntResults").textContent = [...state.results.values()].filter((r) => r.status === "ativo").length;
  $("#cntFav").textContent = (state.info?.favorites || []).length;
  $("#empty").hidden = rows.length > 0 || state.running;
  if (!rows.length && state.tab === "favorites") {
    $("#empty").hidden = false;
    $("#empty").innerHTML = "<p><b>Nenhum favorito.</b></p><p>Clique com o botão direito em um host e escolha <b>Adicionar a favoritos</b>.</p>";
  } else if (!rows.length && state.count > 0) {
    $("#empty").innerHTML = "<p>Nenhum item corresponde à pesquisa ou aos filtros.</p>";
  }
  $("#rows").innerHTML = rows.map((r) => `
    <tr data-ip="${esc(r.ip)}" class="${r.status !== "ativo" ? "dead" : ""}${state.sel === r.ip ? " sel" : ""}">
      <td><span class="dot ${esc(r.status)}"></span>${esc(r.status)}</td>
      <td title="${esc(r.name)}">${esc(r.name || "")}${r.favorite ? '<span class="star" title="Favorito">&#9733;</span>' : ""}</td>
      <td class="c-ip">${esc(r.ip)}</td>
      <td title="${esc(r.vendor)}">${esc(r.vendor || "")}</td>
      <td class="c-mac">${esc(r.mac || "")}</td>
      <td>${esc(r.type || "")}</td>
      <td>${chips(r)}</td>
      <td title="${esc(r.comment)}">${esc(r.comment || "")}</td>
    </tr>`).join("");
  document.querySelectorAll(".grid th").forEach((th) => {
    th.classList.toggle("sorted", th.dataset.sort === state.sort.key);
    th.classList.toggle("asc", th.dataset.sort === state.sort.key && state.sort.asc);
  });
  if (state.sel) renderDetails();
}

function rowData(ip) {
  return state.results.get(ip) || currentRows().find((r) => r.ip === ip);
}

/* ---------- painel de detalhes ---------- */
function renderDetails() {
  const box = $("#details");
  const r = state.sel && rowData(state.sel);
  if (!r) {
    box.innerHTML = '<div class="details-empty">Selecione um host para ver os detalhes.</div>';
    return;
  }
  const kv = [
    ["Status", r.status], ["IP", r.ip], ["MAC", r.mac], ["Fabricante", r.vendor], ["Tipo", r.type],
    ["Nome NetBIOS", r.netbiosName], ["Grupo NetBIOS", r.netbiosGroup], ["Usuário", r.user],
    ["Latência", r.rttMs ? r.rttMs + " ms" : r.status === "ativo" ? "< 1 ms" : ""], ["Data", r.date], ["Comentários", r.comment],
  ].filter(([, v]) => v);
  const svc = (r.services || []).map((s) => {
    const a = ACT[s.key];
    return `<div class="svc"><div><b>${esc(s.name)}</b> <span class="hint">${s.port}</span><small>${esc(s.detail || "")}</small></div>
      ${a ? `<button class="mini" data-act="${a}" data-port="${s.port}">Abrir</button>` : ""}</div>`;
  }).join("") || '<p class="hint">Nenhum serviço encontrado.</p>';
  const shares = (r.shares || []).map((s) =>
    `<div class="svc"><div><b>${esc(s.name)}</b> <span class="hint">${esc(s.type)}</span><small>${esc(s.comment || "")}</small></div>
      <button class="mini" data-act="share" data-share="${esc(s.name)}">Explorar</button></div>`).join("");
  box.innerHTML = `
    <h3>${esc(r.name || r.ip)}</h3><div class="sub">${esc(r.name ? r.ip : "Dispositivo não nomeado")}</div>
    <dl class="kv">${kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
    <div class="sec">Serviços</div>${svc}
    ${shares ? `<div class="sec">Pastas compartilhadas</div>${shares}` : ""}
    <div class="sec">Ferramentas</div>
    <div class="actions">
      <button data-act="ping">Ping</button><button data-act="tracert">Tracert</button>
      <button data-act="explore">Explorar</button><button data-act="rdp">RDP</button>
      <button data-act="ssh">SSH</button><button data-act="telnet">Telnet</button>
      <button data-act="wol">Wake-On-LAN</button><button data-act="shutdown-dlg">Desligar...</button>
      <button data-act="abort">Anular desligamento</button>
    </div>
    <div class="sec">Item</div>
    <div class="actions">
      <button data-act="edit">Renomear / comentário</button>
      <button data-act="${r.favorite ? "unfav" : "fav"}">${r.favorite ? "Remover dos favoritos" : "Adicionar a favoritos"}</button>
      <button data-act="copy-ip">Copiar IP</button><button data-act="copy-mac">Copiar MAC</button>
    </div>`;
}

/* ---------- ações ---------- */
async function doAction(act, ip, extra = {}) {
  const r = rowData(ip) || { ip };
  try {
    switch (act) {
      case "copy-ip": await navigator.clipboard.writeText(r.ip); return toast("IP copiado");
      case "copy-mac": if (!r.mac) return toast("Host sem MAC conhecido", true); await navigator.clipboard.writeText(r.mac); return toast("MAC copiado");
      case "copy-row": await navigator.clipboard.writeText([r.status, r.name, r.ip, r.vendor, r.mac, r.comment].join("\t")); return toast("Linha copiada");
      case "edit": return editItem(r);
      case "fav":
        state.info.favorites = await api("/api/favorite", { op: "add", fav: { ip: r.ip, mac: r.mac || "", name: r.name || "", comment: r.comment || "" } });
        if (state.results.has(r.ip)) state.results.get(r.ip).favorite = true;
        render(); return toast("Adicionado a favoritos");
      case "unfav":
        state.info.favorites = await api("/api/favorite", { op: "remove", fav: { ip: r.ip, mac: r.mac || "" } });
        if (state.results.has(r.ip)) state.results.get(r.ip).favorite = false;
        render(); return toast("Removido dos favoritos");
      case "shutdown-dlg": return shutdownDialog(r);
      case "rescan":
        $("#range").value = r.ip; return startScan();
      case "wol":
        if (!r.mac) return toast("Wake-On-LAN precisa do endereço MAC do host.", true);
    }
    const res = await api("/api/action", { action: act, ip: r.ip, mac: r.mac || "", ...extra });
    if (res.message) toast(res.message);
  } catch (e) {
    toast(e.message, true);
  }
}

function editItem(r) {
  const d = $("#dlgEdit");
  $("#eTitle").textContent = "Editar: " + r.ip;
  $("#eName").value = r.name || "";
  $("#eComment").value = r.comment || "";
  d.onclose = async () => {
    if (d.returnValue !== "ok") return;
    try {
      await api("/api/meta", { ip: r.ip, mac: r.mac || "", name: $("#eName").value.trim(), comment: $("#eComment").value.trim() });
      const live = state.results.get(r.ip);
      if (live) { live.name = $("#eName").value.trim() || live.name; live.comment = $("#eComment").value.trim(); }
      state.info = await api("/api/info");
      render();
    } catch (e) { toast(e.message, true); }
  };
  d.showModal();
}

function shutdownDialog(r) {
  const d = $("#dlgShutdown");
  $("#sTarget").textContent = `${r.name || ""} ${r.ip}`.trim();
  d.onclose = () => {
    if (d.returnValue !== "ok") return;
    const mode = d.querySelector("input[name=sMode]:checked").value;
    doAction(mode, r.ip, { timeout: Number($("#sTimeout").value) || 0, force: $("#sForce").checked, message: $("#sMsg").value });
  };
  d.showModal();
}

function showCtx(x, y, ip) {
  const r = rowData(ip);
  const has = (k) => (r.services || []).some((s) => s.key === k);
  const items = [
    ["rescan", "Examinar novamente"], null,
    has("http") || has("http8080") ? ["http", "Abrir HTTP"] : null,
    has("https") ? ["https", "Abrir HTTPS"] : null,
    has("ftp") ? ["ftp", "Abrir FTP"] : null,
    ["explore", "Explorar (\\\\" + r.ip + ")"],
    ["rdp", "Área de trabalho remota (RDP)"],
    has("ssh") ? ["ssh", "SSH"] : null,
    has("winbox") ? ["winbox", "Winbox"] : null,
    ["ping", "Ping"], ["tracert", "Tracert"],
    ["wol", "Wake-On-LAN"], ["shutdown-dlg", "Desligar..."], ["abort", "Anular desligamento"], "-",
    ["edit", "Renomear / editar comentário"],
    [r.favorite ? "unfav" : "fav", r.favorite ? "Remover dos favoritos" : "Adicionar a favoritos"],
    ["copy-ip", "Copiar IP"], ["copy-mac", "Copiar MAC"], ["copy-row", "Copiar linha"],
  ].filter((i) => i !== null);
  const m = $("#ctx");
  m.innerHTML = items.map((i) => (i === "-" ? "<hr>" : `<button data-act="${i[0]}">${esc(i[1])}</button>`)).join("");
  m.hidden = false;
  const w = m.offsetWidth, h = m.offsetHeight;
  m.style.left = Math.min(x, innerWidth - w - 8) + "px";
  m.style.top = Math.min(y, innerHeight - h - 8) + "px";
  m.dataset.ip = ip;
}

/* ---------- opções ---------- */
function openOptions() {
  const o = state.info.options;
  $("#oThreads").value = o.threads; $("#oThreadsVal").textContent = o.threads;
  $("#oTimeout").value = o.timeoutMs;
  $("#oHigh").checked = o.highAccuracy;
  document.querySelectorAll("[data-g]").forEach((c) => (c.checked = !!o.groups[c.dataset.g]));
  $("#oExtra").value = (o.extraPorts || []).join(", ");
  const d = $("#dlgOptions");
  d.onclose = async () => {
    if (d.returnValue !== "ok") return;
    const groups = {};
    document.querySelectorAll("[data-g]").forEach((c) => (groups[c.dataset.g] = c.checked));
    const extraPorts = $("#oExtra").value.split(/[\s,;]+/).map(Number).filter((n) => n > 0 && n < 65536);
    try {
      state.info.options = await api("/api/options", {
        threads: Number($("#oThreads").value), timeoutMs: Number($("#oTimeout").value),
        highAccuracy: $("#oHigh").checked, groups, extraPorts,
      });
      toast("Opções salvas");
    } catch (e) { toast(e.message, true); }
  };
  d.showModal();
}

/* ---------- abas e eventos ---------- */
function switchTab(t) {
  state.tab = t;
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === t));
  $("#favTools").hidden = t !== "favorites";
  render();
}

function exportAs(kind) {
  $("#exportMenu").hidden = true;
  if (kind === "print") return window.print();
  if (!state.count) return toast("Não há dados a serem salvos", true);
  const scope = $("#expAlive").checked ? "alive" : "all";
  const fmt = kind === "csvc" ? "csv&comma=1" : kind;
  const a = document.createElement("a");
  a.href = `/api/export?fmt=${fmt}&scope=${scope}&t=${encodeURIComponent(TOKEN)}`;
  a.download = "";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function bind() {
  $("#btnScan").onclick = startScan;
  $("#range").addEventListener("keydown", (e) => e.key === "Enter" && !state.running && startScan());
  $("#btnSubnet").onclick = () => {
    const nets = state.info.networks || [];
    if (!nets.length) return toast("Nenhum adaptador de rede IPv4 ativo encontrado.", true);
    $("#range").value = nets.map((n) => n.range).join(", ");
  };
  $("#btnClassC").onclick = () => {
    const nets = state.info.networks || [];
    if (!nets.length) return toast("Nenhum adaptador de rede IPv4 ativo encontrado.", true);
    $("#range").value = [...new Set(nets.map((n) => n.classC))].join(", ");
  };
  $("#btnImport").onclick = () => $("#fileImport").click();
  $("#fileImport").onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const text = await f.text();
    const items = text.split(/\r?\n/).map((l) => l.split(/[;,\t]/)[0].trim()).filter((l) => l && !l.startsWith("#"));
    if (!items.length) return toast("Nenhum endereço IP encontrado no arquivo.", true);
    $("#range").value = items.join(", ");
    e.target.value = "";
    toast(`${items.length} linhas importadas de ${f.name}`);
  };
  $("#search").oninput = render;
  $("#fAlive").onchange = render;
  $("#fDead").onchange = render;
  $("#fDetails").onchange = () => $("#details").classList.toggle("hidden", !$("#fDetails").checked);
  document.querySelectorAll(".tab").forEach((b) => (b.onclick = () => switchTab(b.dataset.tab)));
  document.querySelectorAll(".grid th[data-sort]").forEach((th) => (th.onclick = () => {
    const k = th.dataset.sort;
    state.sort = { key: k, asc: state.sort.key === k ? !state.sort.asc : true };
    render();
  }));
  $("#rows").addEventListener("click", (e) => {
    const tr = e.target.closest("tr");
    if (!tr) return;
    const chip = e.target.closest("[data-act]");
    if (chip) return doAction(chip.dataset.act, tr.dataset.ip, { port: Number(chip.dataset.port) || 0 });
    state.sel = tr.dataset.ip;
    render();
    renderDetails();
  });
  $("#rows").addEventListener("dblclick", (e) => {
    const tr = e.target.closest("tr");
    if (tr) editItem(rowData(tr.dataset.ip));
  });
  $("#rows").addEventListener("contextmenu", (e) => {
    const tr = e.target.closest("tr");
    if (!tr) return;
    e.preventDefault();
    state.sel = tr.dataset.ip;
    render();
    showCtx(e.clientX, e.clientY, tr.dataset.ip);
  });
  $("#ctx").addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    $("#ctx").hidden = true;
    doAction(b.dataset.act, $("#ctx").dataset.ip);
  });
  $("#details").addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]");
    if (b && state.sel) doAction(b.dataset.act, state.sel, { port: Number(b.dataset.port) || 0, share: b.dataset.share || "" });
  });
  document.addEventListener("click", (e) => {
    if (!e.target.closest("#ctx")) $("#ctx").hidden = true;
    if (!e.target.closest(".menu-wrap")) $("#exportMenu").hidden = true;
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") $("#ctx").hidden = true;
    if (e.key === "F5") { e.preventDefault(); if (!state.running) startScan(); }
  });
  $("#btnExport").onclick = () => ($("#exportMenu").hidden = !$("#exportMenu").hidden);
  document.querySelectorAll("[data-exp]").forEach((b) => (b.onclick = () => exportAs(b.dataset.exp)));
  $("#btnOptions").onclick = openOptions;
  $("#oThreads").oninput = () => ($("#oThreadsVal").textContent = $("#oThreads").value);
  $("#btnClear").onclick = async () => {
    if (!confirm("Excluir nomes, comentários e endereços MAC salvos para todos os computadores?")) return;
    await api("/api/clear", {});
    toast("Dados armazenados excluídos");
  };
  $("#btnFavScan").onclick = () => {
    const ips = (state.info.favorites || []).map((f) => f.ip);
    if (!ips.length) return toast("Nenhum favorito.", true);
    $("#range").value = ips.join(", ");
    startScan();
  };
  $("#btnFavAdd").onclick = () => {
    const d = $("#dlgFav");
    d.querySelectorAll("input").forEach((i) => (i.value = ""));
    d.onclose = async () => {
      if (d.returnValue !== "ok") return;
      const mac = $("#fMAC").value.trim().toUpperCase().replace(/-/g, ":");
      if (mac && !/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac)) return toast("Endereço MAC incorreto", true);
      try {
        state.info.favorites = await api("/api/favorite", { op: "add", fav: { ip: $("#fIP").value.trim(), mac, name: $("#fName").value.trim(), comment: $("#fComment").value.trim() } });
        render();
      } catch (e) { toast(e.message, true); }
    };
    d.showModal();
  };
  $("#btnAbout").onclick = () => $("#dlgAbout").showModal();
}

async function heartbeat() {
  try { await api("/api/ping", {}); } catch (_) { /* servidor encerrado */ }
}

(async function init() {
  bind();
  try {
    await loadInfo();
  } catch (e) {
    toast("Falha ao conectar ao serviço local: " + e.message, true);
    return;
  }
  heartbeat();
  setInterval(heartbeat, 20000);
  // Retoma uma verificação em andamento (ex.: recarregou a janela).
  const s = await api("/api/state?since=0");
  if (s.count || s.progress.running) {
    for (const r of s.results) { state.results.set(r.ip, r); state.order.push(r.ip); }
    state.count = s.count;
    updateStatus(s.progress);
    if (s.progress.running) { setRunning(true); poll(); }
  }
  render();
})();
