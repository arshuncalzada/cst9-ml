"""Visual identity for the light-themed ransomware research dashboard."""
STYLE = r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Manrope:wght@400;500;600;700;800&display=swap');
:root {--ink:#17243b;--muted:#76849a;--purple:#7358e7;--border:#e7eaf2;--teal:#16a99d;--bg:#f8f9fc}
html, body, [class*="css"], [data-testid="stApp"] {font-family:'DM Sans',system-ui,sans-serif;color:var(--ink)}
[data-testid="stAppViewContainer"] {background:radial-gradient(ellipse at 95% -7%,rgba(207,200,255,.42) 0%, transparent 39%),radial-gradient(ellipse at 0% 38%,rgba(214,247,245,.32) 0%,transparent 43%),#f8f9fc}
[data-testid="stHeader"] {background:transparent}
.block-container {padding-top:1.9rem;padding-bottom:3.1rem;max-width:1380px}
h1,h2,h3 {font-family:'Manrope',system-ui,sans-serif!important;letter-spacing:-.045em!important;color:var(--ink)!important}
p {line-height:1.6}
[data-testid="stSidebar"] {background:linear-gradient(170deg,#fff 0%,#fdfdff 70%,#f9f7ff 100%);border-right:1px solid #e8e9f1}
[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {gap:.75rem}
[data-testid="stSidebar"] .stRadio [role="radiogroup"] {gap:7px}
[data-testid="stSidebar"] .stRadio label {padding:10px 12px;border-radius:12px;transition:all .2s;min-height:43px}
[data-testid="stSidebar"] .stRadio label:hover {background:#f2efff}
[data-testid="stSidebar"] .stRadio label:has(input:checked) {background:#efebff;border:1px solid #ded5ff}
[data-testid="stSidebar"] .stRadio label:has(input:checked) p {color:#5841cf!important;font-weight:800}
[data-testid="stSidebar"] .stRadio label p {color:#536079;font-size:14px}
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] {display:none}
.st-key-nav [data-testid="stWidgetLabel"] {display:none}
[data-testid="stMetric"] {background:#fff;border:1px solid var(--border);border-radius:16px;padding:20px;box-shadow:0 7px 20px rgba(30,35,81,.035)}
[data-testid="stFileUploaderDropzone"] {background:linear-gradient(135deg,#f9f7ff,#f5fcfc);border:1.5px dashed #c2b7f7;border-radius:16px;padding:22px}
[data-testid="stFileUploaderDropzone"] button {border-radius:10px}
[data-testid="stVerticalBlockBorderWrapper"]>div {border-color:var(--border)!important;border-radius:17px!important;background:rgba(255,255,255,.92)}
[data-testid="stExpander"] {border:1px solid var(--border)!important;border-radius:13px!important;background:#fff}
[data-testid="stExpander"] summary {font-weight:600}
[data-testid="stPlotlyChart"] {border:0}
[data-baseweb="select"]>div,[data-baseweb="input"]>div {border-radius:11px!important;background:#fff}
.stButton>button,.stDownloadButton>button,[data-testid="stFormSubmitButton"]>button {border-radius:11px;min-height:44px;font-weight:700;border-color:#ddd9fa;transition:all .2s}
.stButton>button[kind="primary"],[data-testid="stFormSubmitButton"]>button[kind="primary"] {background:linear-gradient(108deg,#7658eb,#5e78ea);border:0;color:white;box-shadow:0 6px 14px rgba(105,93,223,.17)}
.stButton>button:hover,.stDownloadButton>button:hover {transform:translateY(-1px);border-color:#a89bef}
[data-testid="stForm"] {background:#fff;border:1px solid var(--border);border-radius:17px;padding:22px}
[data-testid="stDataFrame"] {border:1px solid var(--border);border-radius:12px;overflow:hidden}
[data-testid="stProgress"] div[role="progressbar"]>div {background:#7358e7}
[data-testid="stAlert"] {border-radius:12px}
hr {border-color:var(--border)}
.brandmark {display:flex;align-items:center;gap:11px;margin:9px 0 25px}
.brand-icon {width:45px;height:45px;display:grid;place-items:center;background:linear-gradient(138deg,#7d6bee,#4b77ea);box-shadow:0 9px 19px rgba(104,91,222,.24);border-radius:14px;color:white;font-size:26px;font-weight:700}
.brand-text {font-family:Manrope,sans-serif;font-size:18px;font-weight:800;color:#24304a;letter-spacing:-.05em;line-height:1.2}
.brand-sub {font-size:11px;letter-spacing:.13em;color:#94a0b2;font-weight:800}
.nav-label {font-size:11px;color:#9ba6b8;font-weight:800;letter-spacing:.16em;margin-top:17px;margin-bottom:2px}
.side-note {font-size:12px;line-height:1.7;color:#8090a5;background:#f5f3ff;padding:15px;border-radius:13px;border:1px solid #e9e4ff;margin-top:25px}
.side-note strong {color:#6755cb}
.crumb {font-size:12px;font-weight:800;letter-spacing:.15em;color:#8a79de;text-transform:uppercase;margin:3px 0 11px}
.hero {min-height:211px;position:relative;overflow:hidden;background:linear-gradient(114deg,#ffffff 9%,#f7f4ff 65%,#effcff 100%);border:1px solid #e7e4f4;border-radius:24px;padding:35px 40px 33px;box-shadow:0 12px 38px rgba(66,71,127,.06);margin-bottom:25px}
.hero:before {content:'';position:absolute;right:-60px;top:-145px;width:365px;height:365px;border:46px solid rgba(137,114,235,.10);border-radius:50%;pointer-events:none}
.hero:after {content:'';position:absolute;right:90px;bottom:-110px;width:225px;height:225px;background:linear-gradient(120deg,rgba(135,118,235,.14),rgba(67,218,215,.10));border-radius:50%;pointer-events:none}
.hero-kicker {color:#7358e7;letter-spacing:.16em;text-transform:uppercase;font-size:11px;font-weight:800;margin-bottom:9px;position:relative;z-index:1}
.hero h1 {font-size:clamp(26px,3vw,37px)!important;margin:0 0 9px!important;font-weight:800;letter-spacing:-.055em!important;max-width:760px;position:relative;z-index:1}
.hero p {font-size:14px;color:#718098;max-width:680px;margin:0;position:relative;z-index:1;line-height:1.7}
.hero-tags {display:flex;flex-wrap:wrap;gap:8px;margin-top:19px;position:relative;z-index:1}
.pill {border-radius:30px;padding:6px 11px;font-size:11px;font-weight:800;background:#fff;border:1px solid #e8e4fa;color:#7366b6;box-shadow:0 3px 8px rgba(55,50,100,.04)}
.pill.good {background:#ecfbf6;color:#16947f;border-color:#d5f3e8}
.section-h {display:flex;align-items:center;justify-content:space-between;gap:12px;margin:22px 0 13px}
.section-h h2 {font-size:19px!important;font-weight:800!important;margin:0!important}
.section-h span {color:#94a1b5;font-size:12px;font-weight:600}
.kpi-card {background:#fff;border:1px solid var(--border);border-radius:17px;padding:19px 19px 18px;min-height:141px;box-shadow:0 8px 26px rgba(34,38,78,.045);position:relative;overflow:hidden}
.kpi-card:after {content:'';width:112px;height:112px;border:26px solid rgba(116,89,231,.035);border-radius:50%;position:absolute;right:-50px;top:-58px}
.kpi-top {display:flex;align-items:center;justify-content:space-between;gap:6px}
.kpi-label {font-size:12px;font-weight:700;color:#7c89a0;letter-spacing:.012em}
.kpi-icon {width:31px;height:31px;border-radius:9px;background:#f0edff;display:grid;place-items:center;color:#7156e5;font-size:18px;font-weight:700}
.kpi-value {font-family:'Manrope',sans-serif;font-size:clamp(22px,2.5vw,29px);letter-spacing:-.05em;font-weight:800;color:#202943;margin:13px 0 2px}
.kpi-foot {font-size:11px;color:#97a3b4}
.panel {background:white;border:1px solid var(--border);border-radius:18px;box-shadow:0 6px 24px rgba(40,45,89,.035);padding:19px 20px;margin-bottom:14px}
.panel h3 {font-size:15px!important;letter-spacing:-.03em!important;margin:0 0 4px!important;font-weight:800!important}
.panel p.note {font-size:12px;color:#8591a3;margin:0 0 6px}
.swatch-line {display:flex;align-items:center;flex-wrap:wrap;gap:15px;color:#77869d;font-size:12px}
.swatch {width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:5px}
.stat-row {display:flex;align-items:center;justify-content:space-between;padding:13px 0;border-bottom:1px solid #f0f2f7;font-size:13px}
.stat-row:last-child {border-bottom:0}
.stat-row span {color:#8290a3}
.stat-row strong {color:#28344d;font-weight:800}
.insight {padding:15px 17px;border-radius:13px;background:#f7f5ff;border:1px solid #ece8ff;color:#615d83;font-size:12px;line-height:1.6;margin:9px 0}
.insight strong {color:#6152bd}
.result-card {background:linear-gradient(115deg,#f2fffb,#f9fcff);border:1px solid #cdece2;border-left:4px solid #23af99;padding:20px 22px;border-radius:16px;margin:15px 0}
.result-card.flag {background:linear-gradient(115deg,#fff5f5,#fff9fb);border-color:#f5d0d3;border-left-color:#e66b78}
.result-mini {font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:800;color:#78968c}
.result-card.flag .result-mini {color:#d37886}
.result-main {font-family:Manrope,sans-serif;font-size:25px;font-weight:800;letter-spacing:-.05em;color:#225e53;margin:4px 0}
.result-card.flag .result-main {color:#a74957}
.result-text {font-size:12px;color:#7b8b96;overflow-wrap:anywhere}
.small-text {font-size:12px;color:#8591a4;line-height:1.7}
.footer {font-size:11px;color:#9aa6b8;margin-top:38px;border-top:1px solid #e9ecf3;padding-top:18px}
@media (max-width:750px) {.block-container{padding-top:1.1rem}.hero{padding:27px 23px;min-height:auto}.hero:before{right:-210px}.panel{padding:16px 14px}.kpi-card{min-height:125px;padding:16px}.hero h1{font-size:26px!important}}
</style>
"""
