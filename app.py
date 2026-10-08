"""Streamlit interface for the bundled, pretrained ransomware classifier."""
from html import escape
from pathlib import Path
import json
import pandas as pd
import streamlit as st
from model import FEATURES, load_saved_model, predict, metrics
from pe_extractor import MAX_PE_BYTES, PEFormatError, extract_pe_features

st.set_page_config(page_title='Ransomware Detection Lab', page_icon='🛡', layout='wide')
st.markdown('''<style>
.block-container {max-width:1120px;padding-top:2.6rem;padding-bottom:3rem}
[data-testid="stAppViewContainer"] {background:radial-gradient(ellipse at 90% 0%,#14302e 0%,#0b111b 48%)}
h1,h2,h3 {font-weight:600!important;letter-spacing:-.035em}
h1 {font-size:2.65rem!important;line-height:1.15!important}
p {line-height:1.6}
.brand {display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #27333f;padding-bottom:22px;margin-bottom:30px;gap:16px}
.brand-name {font:600 16px ui-monospace,monospace;letter-spacing:.06em;color:#e8eff3}
.shield {display:inline-block;color:#69e5b3;margin-right:10px;font-size:23px}
.status {font:13px ui-monospace,monospace;color:#83e9bb;border:1px solid #315348;background:#142920;padding:8px 12px;border-radius:4px;white-space:nowrap}
.intro {color:#a8b7c6;margin:0 0 30px;font-size:17px}
[data-baseweb="tab-list"] {gap:24px;border-bottom:1px solid #27333f;margin-bottom:26px}
[data-baseweb="tab"] {font-size:16px;padding:14px 0}
[data-testid="stVerticalBlockBorderWrapper"]>div {border-color:#2a3945!important;border-radius:8px!important}
[data-testid="stFileUploaderDropzone"] {background:#101d28;border:1px dashed #446357;border-radius:6px;padding:30px 20px}
[data-testid="stMetric"] {background:#111e29;border:1px solid #2a3945;border-radius:6px;padding:18px}
[data-testid="stMetricLabel"] {color:#abbac7}
[data-testid="stMetricValue"] {font-family:ui-monospace,monospace;font-size:1.8rem}
.stButton>button[kind="primary"] {border-radius:4px;font-weight:600;min-height:46px}
.empty {padding:42px 20px;text-align:center;border:1px solid #2a3945;border-radius:6px;background:#101923;margin-top:20px;color:#acbbc8}
.empty-icon {font:36px ui-monospace,monospace;color:#638674;margin-bottom:12px}
.result {border:1px solid #376450;border-left:4px solid #69e5b3;padding:22px 26px;background:#11271f;border-radius:6px;margin:18px 0}
.result.flagged {border-color:#844747;border-left-color:#ff8585;background:#2b1a21}
.result h2 {padding:0!important;margin:5px 0 8px!important}
.result p {margin:0;color:#c2ccd5;overflow-wrap:anywhere}
.result-label {font:13px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.1em;color:#b8c8d4}
.footer {border-top:1px solid #27333f;margin-top:32px;padding-top:18px;color:#9eafbe;font-size:14px}
@media(max-width:600px) {.block-container{padding-top:1.5rem}h1{font-size:2rem!important}.brand{align-items:flex-start;flex-direction:column}[data-baseweb="tab-list"]{gap:18px}.status{font-size:12px}}
</style>''', unsafe_allow_html=True)

@st.cache_resource(show_spinner='Loading model…')
def load_model(version):
    return load_saved_model()

try:
    artifact_dir = Path(__file__).parent / 'artifacts'
    versions = tuple(p.stat().st_mtime_ns for p in sorted(artifact_dir.glob('*')) if p.is_file())
    bundle = load_model(versions)
except (OSError, ValueError, KeyError, EOFError) as exc:
    st.error(f'Could not load the saved model: {exc}')
    st.info('Restore the three .joblib files in the artifacts folder, then restart the app.')
    st.stop()

st.markdown('<div class="brand"><div class="brand-name"><span class="shield">◇</span>DETECTION LAB</div><div class="status">● &nbsp; Trained model loaded</div></div>', unsafe_allow_html=True)
st.title('Ransomware detection')
st.markdown('<p class="intro">Inspect a Windows executable with the trained model.</p>', unsafe_allow_html=True)
scan, manual, performance = st.tabs(['File scan', 'Manual analysis', 'Model results'])
THRESHOLD = .50

def show_result(outcome, name):
    flagged = outcome['Prediction'] == 'Ransomware'
    css = 'result flagged' if flagged else 'result'
    label = 'Ransomware detected' if flagged else 'Classified as benign'
    st.markdown(f'<div class="{css}"><div class="result-label">Model prediction</div><h2>{label}</h2><p>{escape(name)}</p></div>', unsafe_allow_html=True)
    st.metric('Ransomware probability', f"{outcome['Ransomware probability']:.2%}")
    st.progress(float(outcome['Ransomware probability']))
    if bool(outcome['Unseen machine code']):
        st.warning('This processor type was not seen during training. The prediction may be unreliable.')

with scan:
    left, right = st.columns([1.75, 1], gap='large')
    with left:
        st.subheader('Scan a file')
        uploaded = st.file_uploader('Windows executable · .exe or .dll · up to 20 MiB', type=['exe', 'dll'], key='uploaded_pe')
        analyze = st.button('Analyze file', type='primary', disabled=uploaded is None, use_container_width=True)
    with right:
        with st.container(border=True):
            st.subheader('Static inspection')
            st.write('Files are read, never executed.')
            st.divider()
            st.write('**Model**  ·  Logistic regression')
            st.write('**Input**  ·  Windows PE file')
            st.write('**Decision threshold**  ·  50%')
    # Changing or removing the selected file must never show an old verdict.
    current_id = (uploaded.name, uploaded.size, uploaded.file_id) if uploaded is not None else None
    if st.session_state.get('selected_file') != current_id:
        st.session_state.pop('scan_result', None)
        st.session_state.selected_file = current_id
    if analyze and uploaded is not None:
        st.session_state.pop('scan_result', None)
        try:
            if uploaded.size > MAX_PE_BYTES:
                raise PEFormatError('The file exceeds the 20 MiB limit.')
            with st.spinner('Analyzing file…'):
                info = extract_pe_features(uploaded.getvalue())
                extracted = pd.DataFrame([info.features], columns=FEATURES)
                outcome = predict(bundle, extracted, THRESHOLD).iloc[0]
            st.session_state.scan_result = (uploaded.name, info, extracted, outcome)
        except (PEFormatError, ValueError, TypeError) as exc:
            st.error(f'Unable to analyze this file: {exc}')
    if 'scan_result' in st.session_state:
        name, info, extracted, outcome = st.session_state.scan_result
        show_result(outcome, name)
        a, b = st.columns(2)
        a.metric('File format', info.pe_kind)
        b.metric('File size', f'{info.size_bytes / 1024:.1f} KiB')
        if info.is_dll != name.lower().endswith('.dll'):
            st.warning('The file extension does not match its PE header type.')
        with st.expander('File details'):
            st.write('**SHA-256**')
            st.code(info.sha256, language=None)
            st.dataframe(extracted.T.rename(columns={0: 'Value'}), width='stretch')
            st.write(info.wallet_scan_note)
        report = {'filename': name, 'sha256': info.sha256, 'prediction': str(outcome['Prediction']),
                  'ransomware_probability': float(outcome['Ransomware probability']),
                  'threshold': THRESHOLD, 'features': info.features,
                  'limitations': 'Experimental static classifier. A benign prediction does not guarantee safety. Real-file detection accuracy has not been validated.'}
        st.download_button('Download report', json.dumps(report, indent=2), file_name='scan_report.json', mime='application/json')
    elif not analyze:
        st.markdown('<div class="empty"><div class="empty-icon">[ + ]</div><strong>Ready for inspection</strong><p>Select a file and run an analysis.</p></div>', unsafe_allow_html=True)

with manual:
    st.subheader('Analyze PE features')
    st.write('Enter a file’s extracted values for a single prediction.')
    with st.form('feature_input'):
        cols = st.columns(3)
        values = {feature: cols[i % 3].number_input(feature, min_value=0, max_value=2**53-1, value=0, step=1)
                  for i, feature in enumerate(FEATURES)}
        submitted = st.form_submit_button('Analyze record', type='primary')
    if submitted:
        try:
            record = pd.DataFrame([values], columns=FEATURES)
            outcome = predict(bundle, record, THRESHOLD).iloc[0]
            show_result(outcome, 'Submitted feature record')
            with st.expander('Submitted values'):
                st.dataframe(record.T.rename(columns={0: 'Value'}), width='stretch')
        except (ValueError, TypeError) as exc:
            st.error(f'Unable to analyze this record: {exc}')

with performance:
    st.subheader('Model evaluation')
    if bundle['evaluation']:
        summary = metrics(bundle, THRESHOLD)
        for col, label, key in zip(st.columns(4), ['Accuracy', 'Precision', 'Recall', 'F1 score'],
                                   ['Accuracy', 'Ransomware precision', 'Ransomware recall', 'Ransomware F1']):
            col.metric(label, f'{summary[key]:.2%}')
        st.write(f"Saved test split · {bundle['train_rows']:,} training records · {bundle['test_rows']:,} test records")
        st.subheader('Confusion matrix')
        st.dataframe(pd.DataFrame(summary['confusion_matrix'], index=['Actual ransomware', 'Actual benign'],
                     columns=['Predicted ransomware', 'Predicted benign']), width='stretch')
        st.warning('The original notebook scaled data before splitting. These test scores may be optimistic; they do not measure accuracy on uploaded executables.')
    else:
        st.info('No saved evaluation results are available.')
    with st.expander('Model and limitations'):
        st.write('The app loads the saved classifier, scaler and feature list. It does not train a model or require a dataset upload.')
        st.write('Fifteen PE features are extracted, derived features are added, and values are transformed with the saved scaler. Labels: 0 = ransomware, 1 = benign.')
        st.write('The Bitcoin-address feature is heuristic. Its extraction may differ from the training dataset. File scanning has not been independently validated.')
        if bundle['evaluation']:
            st.write('Data source: ' + bundle['evaluation'].get('data_source', 'Not recorded'))
            st.write('Selected parameters:', bundle['evaluation'].get('best_params', {}))
        weights = pd.Series(bundle['classifier'].coef_[0], index=bundle['columns'])
        st.bar_chart(weights.reindex(weights.abs().nlargest(12).index).sort_values(), horizontal=True, color='#69e5b3')
        st.write('Positive coefficients favor benign; negative coefficients favor ransomware.')

st.markdown('<div class="footer">Research prototype. A benign prediction does not guarantee safety. Analyze untrusted samples only in an isolated local environment.</div>', unsafe_allow_html=True)
