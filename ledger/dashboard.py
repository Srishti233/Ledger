"""The single self-contained dashboard page (no external assets, no build step)."""

from __future__ import annotations

import html

from .verifier import WHAT_NOT_PROVES, WHAT_PROVES

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ledger: anchored audit logs</title>
<style>
:root{
  --paper:#f2f5f7; --rule:#c8d4de; --ink:#16223a; --muted:#52627a; --margin:#d4574c;
  --ok:#17775a; --bad:#b3261e; --warn:#8a5a00; --card:#fbfcfd; --focus:#1a56db;
  --serif:ui-serif,"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){
  :root{--paper:#0f1724;--rule:#243247;--ink:#e6ecf5;--muted:#9aaac0;--margin:#e0685d;
        --ok:#4cc79d;--bad:#ff8a80;--warn:#e0b050;--card:#152033;--focus:#7aa7ff}
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 var(--sans)}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
header,main{max-width:1040px;margin:0 auto;padding:0 20px}
header{padding-top:36px;padding-bottom:8px}
h1{font:600 clamp(2.2rem,5vw,3.4rem)/1.05 var(--serif);margin:0;letter-spacing:-.01em}
.lede{color:var(--muted);margin:.5rem 0 0;max-width:62ch}
#statusline{margin:1rem 0 0;font-family:var(--mono);font-size:.85rem;color:var(--muted)}
#statusline b{color:var(--ink)}
section{margin:2.2rem 0}
h2{font:600 1.35rem/1.2 var(--serif);margin:0 0 .8rem}
/* the verify desk is the memorable element */
.desk{background:var(--card);border:2px solid var(--ink);padding:22px 22px 20px 34px;position:relative;
  background-image:repeating-linear-gradient(transparent 0 31px,var(--rule) 31px 32px)}
.desk:before{content:"";position:absolute;left:18px;top:0;bottom:0;width:3px;
  border-left:1px solid var(--margin);border-right:1px solid var(--margin)}
.desk label{font:600 1.1rem var(--serif);display:block;margin-bottom:.5rem}
.row{display:flex;gap:10px;flex-wrap:wrap}
input[type=number]{font:600 1.6rem var(--mono);width:9ch;padding:6px 10px;border:2px solid var(--ink);
  background:var(--card);color:var(--ink)}
button{font:600 1rem var(--sans);padding:10px 18px;border:2px solid var(--ink);background:var(--ink);
  color:var(--paper);cursor:pointer}
button.alt{background:transparent;color:var(--ink)}
button:disabled{opacity:.55;cursor:wait}
.hint{color:var(--muted);font-size:.9rem;margin:.6rem 0 0}
#result{margin-top:18px}
.stamp{display:inline-block;border:3px solid currentColor;padding:6px 14px;font:700 1.25rem var(--serif);
  letter-spacing:.04em;transform:rotate(-2deg);background:var(--card)}
.stamp.verified{color:var(--ok)} .stamp.tamper_detected{color:var(--bad)} .stamp.inconclusive{color:var(--warn)}
@media (prefers-reduced-motion:no-preference){.stamp.fresh{animation:press .22s ease-out}}
@keyframes press{from{transform:rotate(-2deg) scale(1.25);opacity:.2}to{transform:rotate(-2deg) scale(1);opacity:1}}
.checks{list-style:none;margin:14px 0 0;padding:0;background:var(--card);border:1px solid var(--rule)}
.checks li{padding:6px 10px;border-bottom:1px solid var(--rule);font-size:.92rem}
.checks li:last-child{border-bottom:0}
.tag{font:700 .75rem var(--mono);margin-right:8px;padding:1px 6px;border:1px solid currentColor}
.tag.pass{color:var(--ok)} .tag.fail{color:var(--bad)} .tag.skipped{color:var(--muted)}
.table-wrap{overflow-x:auto;background:var(--card);border:1px solid var(--rule)}
table{border-collapse:collapse;width:100%;min-width:640px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--rule);font-size:.9rem;vertical-align:top}
th{font-weight:600;color:var(--muted)}
td.mono,.mono{font-family:var(--mono);font-size:.8rem;word-break:break-all}
.proofbox{display:grid;grid-template-columns:1fr 1fr;gap:0;border:2px solid var(--ink);background:var(--card)}
.proofbox>div{padding:18px 20px}
.proofbox>div+div{border-left:2px solid var(--ink)}
.proofbox h3{font:600 1.1rem var(--serif);margin:0 0 .5rem}
.proofbox .yes h3{color:var(--ok)} .proofbox .no h3{color:var(--bad)}
@media (max-width:700px){.proofbox{grid-template-columns:1fr}.proofbox>div+div{border-left:0;border-top:2px solid var(--ink)}}
footer{max-width:1040px;margin:0 auto;padding:10px 20px 40px;color:var(--muted);font-size:.85rem}
</style>
</head>
<body>
<header>
  <h1>Ledger</h1>
  <p class="lede">Hashes of Aegis audit rows and Gauntlet findings, batched into Merkle roots and written to a blockchain, so a later edit to any of them can be caught without trusting any single server.</p>
  <p id="statusline" aria-live="polite">loading status...</p>
</header>
<main>
  <section aria-labelledby="verify-h">
    <h2 id="verify-h">Check a record</h2>
    <div class="desk">
      <label for="rid">Record number</label>
      <div class="row">
        <input id="rid" type="number" min="1" step="1" value="1" inputmode="numeric">
        <button id="go" type="button">Verify against the chain</button>
        <button id="gob" class="alt" type="button">Verify its whole batch</button>
      </div>
      <p class="hint">Re-checks Ledger's own index against the live chain, and re-hashes the source data when it is reachable.</p>
      <div id="result" aria-live="polite"></div>
    </div>
  </section>

  <section aria-labelledby="batches-h">
    <h2 id="batches-h">Recent batches</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Batch</th><th>Source</th><th>Records</th><th>Block</th><th>Gas</th><th>Transaction</th></tr></thead>
      <tbody id="batches"><tr><td colspan="6">loading...</td></tr></tbody>
    </table></div>
  </section>

  <section aria-labelledby="proves-h">
    <h2 id="proves-h">What this does and does not prove</h2>
    <div class="proofbox">
      <div class="yes"><h3>Proves</h3><p>__PROVES__</p></div>
      <div class="no"><h3>Does not prove</h3><p>__NOT_PROVES__</p></div>
    </div>
  </section>
</main>
<footer>Local development chain by default: test ETH with no real value. See SECURITY.md for the trust boundary.</footer>
<script>
const $ = (id) => document.getElementById(id);
function el(tag, props, ...kids){const e=document.createElement(tag);
  Object.assign(e,props||{});kids.forEach(k=>e.append(k));return e;}
async function getJSON(url){const r=await fetch(url);if(!r.ok){let m=r.statusText;
  try{m=(await r.json()).detail||m}catch(_){}throw new Error(m)}return r.json();}
function when(iso){return iso?new Date(iso).toLocaleString():"never"}
async function loadStatus(){
  try{const s=await getJSON("/status");const c=s.chain;const line=$("statusline");line.textContent="";
    line.append("chain ",el("b",{textContent:c.connected?"connected":"UNREACHABLE"}),
      c.local?" (local dev chain)":" (non-local)"," | pending ",el("b",{textContent:String(s.pending)}),
      " | anchored ",el("b",{textContent:String(s.anchored)})," | last anchor ",
      el("b",{textContent:when(s.last_anchor_at)}));
  }catch(e){$("statusline").textContent="status unavailable: "+e.message}
}
async function loadBatches(){
  const body=$("batches");
  try{const rows=await getJSON("/batches?limit=15");body.textContent="";
    if(!rows.length){body.append(el("tr",{},el("td",{colSpan:6,textContent:"No batches anchored yet."})));return}
    rows.forEach(b=>{
      const tx=el("td",{className:"mono"});
      if(b.explorer_url&&/^https?:\/\//.test(b.explorer_url))
        tx.append(el("a",{href:b.explorer_url,textContent:b.tx_hash,target:"_blank",rel:"noopener noreferrer"}));
      else tx.textContent=b.tx_hash;
      body.append(el("tr",{},el("td",{textContent:"#"+b.id+" (chain "+b.chain_batch_id+")"}),
        el("td",{textContent:b.source_label}),el("td",{textContent:String(b.record_count)}),
        el("td",{textContent:String(b.block_number)}),el("td",{textContent:String(b.gas_used)}),tx));
    });
  }catch(e){body.textContent="";body.append(el("tr",{},el("td",{colSpan:6,textContent:"could not load batches: "+e.message})))}
}
const LABEL={verified:"VERIFIED",tamper_detected:"TAMPER DETECTED",inconclusive:"INCONCLUSIVE"};
function show(v){
  const out=$("result");out.textContent="";
  out.append(el("span",{className:"stamp fresh "+v.status,textContent:v.scope+": "+(LABEL[v.status]||v.status)}));
  const ul=el("ul",{className:"checks"});
  v.checks.forEach(c=>ul.append(el("li",{},el("span",{className:"tag "+c.status,textContent:c.status}),
    el("b",{textContent:c.name+": "}),c.detail)));
  out.append(ul);
  (v.causes||[]).forEach(c=>out.append(el("p",{},el("b",{textContent:c.code+": "}),c.meaning)));
  const proven=el("p",{className:"hint"});proven.append(el("b",{textContent:"Proven: "}),
    (v.what_was_proven||[]).join(" ")||"nothing");out.append(proven);
  const np=el("p",{className:"hint"});np.append(el("b",{textContent:"Not proven / not checked: "}),
    (v.what_was_not_proven||[]).join(" "));out.append(np);
}
async function run(kind){
  const id=parseInt($("rid").value,10);if(!(id>0)){$("result").textContent="Enter a positive number.";return}
  $("go").disabled=$("gob").disabled=true;
  try{
    let url="/verify/"+id;
    if(kind==="batch"){const rec=await getJSON("/records/"+id);
      if(!rec.batch){throw new Error("record "+id+" is not anchored yet")}
      url="/verify/batch/"+rec.batch.id+"?full=true"}
    show(await getJSON(url));
  }catch(e){const out=$("result");out.textContent="";out.append(el("span",{className:"stamp inconclusive fresh",textContent:"ERROR: "+e.message}))}
  finally{$("go").disabled=$("gob").disabled=false;loadStatus()}
}
$("go").addEventListener("click",()=>run("record"));
$("gob").addEventListener("click",()=>run("batch"));
loadStatus();loadBatches();setInterval(()=>{loadStatus();loadBatches()},15000);
</script>
</body>
</html>
"""


def render_dashboard() -> str:
    return PAGE.replace("__PROVES__", html.escape(WHAT_PROVES)).replace(
        "__NOT_PROVES__", html.escape(WHAT_NOT_PROVES)
    )
