"""White dashboard theme and layout."""

STYLE = r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Manrope:wght@400;500;600;700;800&display=swap');
:root {--text:#202b3d; --purple:#6757d8; --border:#e5e8f1; --muted:#77839a}
html, body, [data-testid="stApp"] {font-family:'DM Sans',system-ui,sans-serif; color:var(--text)}
[data-testid="stAppViewContainer"] {background:radial-gradient(ellipse at 96% 0%, rgba(224,216,255,.42), transparent 34%),radial-gradient(ellipse at 1% 90%, rgba(224,246,245,.5), transparent 34%),#f9fafe}
[data-testid="stHeader"] {background:transparent}
.block-container {max-width:1350px; padding-top:2rem; padding-bottom:3rem}
h1,h2,h3 {font-family:'Manrope',system-ui,sans-serif; color:var(--text)!important; letter-spacing:-.042em!important}
[data-testid="stSidebar"] {background:#fff; border-right:1px solid var(--border)}
[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {gap:.6rem}
[data-testid="stSidebar"] .stRadio [role="radiogroup"] {gap:7px}
[data-testid="stSidebar"] .stRadio label {min-height:44px; padding:11px 12px; border-radius:12px; transition:background .15s}
[data-testid="stSidebar"] .stRadio label:hover {background:#f5f3ff}
[data-testid="stSidebar"] .stRadio label:has(input:checked) {background:#efedff}
[data-testid="stSidebar"] .stRadio label:has(input:checked) p {color:#5444c6; font-weight:700}
[data-testid="stSidebar"] .stRadio label p {color:#526076; font-size:14px}
.brand {display:flex; gap:11px; align-items:center; font-family:Manrope,system-ui,sans-serif; font-size:21px; font-weight:800; color:#24314b; letter-spacing:-.05em; margin:10px 0 34px}
.brand-mark {display:grid;place-items:center; width:43px;height:43px;background:linear-gradient(140deg,#7966ed,#5c77e7);color:white;border-radius:14px;box-shadow:0 9px 18px rgba(110,93,215,.17);font-size:24px}
.page-heading {position:relative;overflow:hidden;padding:34px 37px;margin-bottom:25px; border:1px solid #e5e4f3; border-radius:22px;background:linear-gradient(112deg,#fff 15%,#f8f6ff 70%,#effcff 100%);box-shadow:0 9px 31px rgba(45,51,100,.045)}
.page-heading:after {content:'';position:absolute;width:240px;height:240px;border:43px solid rgba(112,98,230,.07);border-radius:50%;right:-65px;top:-135px;pointer-events:none}
.page-heading h1 {position:relative;z-index:1;font-size:clamp(28px,3.4vw,42px)!important;font-weight:800!important;margin:0!important}
.section-title {font-size:19px!important;font-weight:800!important;margin:26px 0 14px!important}
.panel-title {font-size:16px!important;font-weight:800!important;margin:0 0 12px!important}
.stat-card {background:#fff;border:1px solid var(--border);border-radius:16px;padding:21px 22px;min-height:123px;box-shadow:0 6px 24px rgba(38,46,95,.035);position:relative;overflow:hidden}
.stat-card:after {content:'';width:120px;height:120px;border:24px solid rgba(114,92,224,.033);border-radius:50%;position:absolute;right:-62px;top:-66px}
.stat-label {font-size:13px;font-weight:600;color:#717f96}
.stat-value {font-family:Manrope,system-ui,sans-serif;font-size:clamp(23px,2.6vw,32px);font-weight:800;color:#252f47;letter-spacing:-.055em;margin-top:15px;line-height:1.2}
[data-testid="stVerticalBlockBorderWrapper"]>div {border-color:var(--border)!important;border-radius:17px!important;background:rgba(255,255,255,.93)}
[data-testid="stVerticalBlockBorderWrapper"] [data-testid="stVerticalBlock"] {gap:.7rem}
[data-testid="stMetric"] {background:#fff;border:1px solid var(--border);padding:17px;border-radius:15px}
[data-testid="stMetricLabel"] {color:#6d7991}
.detail-row {display:flex;align-items:center;justify-content:space-between;gap:10px;padding:15px 0;border-bottom:1px solid #f0f1f6;font-size:14px}
.detail-row:last-child {border-bottom:0}
.detail-row span {color:#6c798d}
.detail-row strong {color:#23324b;font-weight:700}
.legend {display:flex;justify-content:center;gap:26px;margin:2px 0 12px;flex-wrap:wrap;font-size:13px;color:#67768f}
.legend span {display:inline-flex;align-items:center}
.legend i {display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px}
.key-purple {background:#7358e7}.key-teal {background:#16a99d}.key-coral {background:#ef7e84}
.prediction {border:1px solid #cde9df;border-left:4px solid #21a88f;background:#f7fffc;padding:21px 22px;border-radius:14px;margin:13px 0 20px}
.prediction.threat {border-color:#f0d1d5;border-left-color:#df6874;background:#fff8f8}
.prediction-label {font-size:13px;font-weight:700;color:#6e8d82}
.prediction.threat .prediction-label {color:#b97780}
.prediction-name {font-family:Manrope,sans-serif;font-weight:800;font-size:30px;letter-spacing:-.04em;color:#236955}
.prediction.threat .prediction-name {color:#a74957}
.prediction-file {font-size:14px;color:#66758c;overflow-wrap:anywhere;margin-top:3px}
.stButton>button,.stDownloadButton>button,[data-testid="stFormSubmitButton"]>button {border-radius:11px;min-height:43px;font-weight:700;border-color:#dcd8f7}
.stButton>button[kind="primary"],[data-testid="stFormSubmitButton"]>button[kind="primary"] {background:linear-gradient(112deg,#7358e7,#6179e5);border:0;color:#fff}
[data-baseweb="select"]>div,[data-baseweb="input"]>div {border-radius:10px!important;background:#fff}
[data-testid="stFileUploaderDropzone"] {background:linear-gradient(135deg,#faf8ff,#f7fcfc);border:1px dashed #c3b9ee;border-radius:14px}
[data-testid="stExpander"] {border:1px solid var(--border)!important;border-radius:14px!important;background:#fff}
[data-testid="stForm"] {background:#fff;border:1px solid var(--border);border-radius:16px;padding:21px}
[data-testid="stAlert"] {border-radius:12px}
@media(max-width:760px) {.block-container{padding-top:1.1rem}.page-heading{padding:26px 24px}.stat-card{padding:17px;min-height:110px}}
</style>
"""
