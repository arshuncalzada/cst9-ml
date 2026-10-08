from pathlib import Path
import pandas as pd
import streamlit as st
from model import DATA_PATH, FEATURES, load_saved_model, predict, metrics

st.set_page_config(page_title='Ransomware Detection Lab', page_icon='🛡️', layout='wide')
st.markdown('''<style>
.block-container {max-width:1250px;padding-top:2.5rem}
[data-testid="stMetric"] {background:#152238;border:1px solid #2b405b;border-radius:12px;padding:16px}
h1 {letter-spacing:-1.4px}
</style>''', unsafe_allow_html=True)

@st.cache_resource(show_spinner='Loading your saved notebook model…')
def load_model(version):
    return load_saved_model()

st.caption('STATIC PE ANALYSIS  /  MACHINE LEARNING LAB')
st.title('Ransomware Detection Lab')
st.write('Explore file features, classify records, and understand your model’s performance.')
try:
    artifact_dir = Path(__file__).parent / 'artifacts'
    versions = tuple(p.stat().st_mtime_ns for p in sorted(artifact_dir.glob('*')) if p.is_file())
    bundle = load_model(versions)
except (OSError, ValueError) as exc:
    st.error(f'Could not load your saved model: {exc}')
    st.info('Run NOTEBOOK_EXPORT_CELL.py as a cell inside your trained notebook. Copy the exported artifacts folder beside app.py. See README.md.')
    st.stop()

with st.sidebar:
    st.title('🛡️ Detection Lab')
    st.caption('LOGISTIC REGRESSION')
    st.divider()
    threshold = st.slider('Ransomware threshold', .05, .95, .50, .05,
                          help='Classify as ransomware when its model probability reaches this value.')
    st.caption('Lower thresholds flag more files and may increase false positives.')
    st.divider()
    st.write('**Saved notebook model**')
    st.caption('No model training takes place in this app.')
    st.info('Research prototype. A benign prediction is not proof that a file is safe.')

summary = metrics(bundle, threshold) if bundle['evaluation'] else None
if summary:
    for col, label in zip(st.columns(4), ['Accuracy', 'Ransomware precision', 'Ransomware recall', 'Ransomware F1']):
        col.metric(label, f'{summary[label]:.2%}')
    st.caption('Exported notebook test split. Ransomware is the positive class in this UI.')
else:
    st.info('Export evaluation.json with the notebook cell to show evaluation metrics.')
single, batch, performance, about = st.tabs(['Single prediction', 'Batch CSV', 'Model performance', 'How it works'])

with single:
    st.subheader('Inspect one feature record')
    st.write('Enter pre-extracted numeric features or load a dataset example. No executable upload is needed.')
    source = st.selectbox('Starting values', ['Manual entry (zeros)', 'Dataset example: benign', 'Dataset example: ransomware'])
    if source == 'Manual entry (zeros)':
        defaults = dict.fromkeys(FEATURES, 0)
    else:
        label = 1 if source.endswith('benign') else 0
        defaults = bundle['data'].loc[bundle['data'].Benign == label, FEATURES].iloc[0].to_dict()
        st.caption('Dataset examples demonstrate the UI; they are not independent validation samples.')
    with st.form('feature_input'):
        cols = st.columns(3)
        values = {}
        for i, feature in enumerate(FEATURES):
            values[feature] = cols[i % 3].number_input(feature, min_value=0, max_value=2**53-1,
                value=int(defaults[feature]), step=1, key=f'{source}_{feature}')
        submitted = st.form_submit_button('Analyze record', type='primary')
    if submitted:
        st.session_state['single_values'] = values
    if 'single_values' in st.session_state:
        record = pd.DataFrame([st.session_state['single_values']])
        result = predict(bundle, record, threshold).iloc[0]
        st.divider()
        st.caption('LAST SUBMITTED RECORD · Submit again after editing fields')
        if result['Prediction'] == 'Ransomware':
            st.error('Prediction: Ransomware')
        else:
            st.success('Prediction: Benign')
        st.metric('Estimated ransomware probability', f"{result['Ransomware probability']:.2%}")
        st.progress(float(result['Ransomware probability']))
        st.caption(f'Decision threshold: {threshold:.0%}. Model probabilities are not calibrated risk guarantees.')
        if result['Unseen machine code']:
            st.warning('This machine code was not present in training. Treat this result with extra caution.')
        with st.expander('Submitted feature values'):
            st.dataframe(record, hide_index=True, width='stretch')

with batch:
    st.subheader('Classify a CSV batch')
    st.write('One file record per row. Use the 15 raw feature columns; FileName and md5Hash are optional. Benign is ignored during prediction.')
    sample = bundle['data'].groupby('Benign', group_keys=False).head(3)[['FileName'] + FEATURES]
    st.download_button('Download example CSV', sample.to_csv(index=False), 'example_features.csv', 'text/csv')
    uploaded = st.file_uploader('Upload feature records', type=['csv'], help='Maximum 20 MB and 100,000 rows.')
    if uploaded is not None:
        try:
            if uploaded.size > 20 * 1024 * 1024:
                raise ValueError('Please keep uploads below 20 MB.')
            frame = pd.read_csv(uploaded)
            result = predict(bundle, frame, threshold)
            c1, c2, c3 = st.columns(3)
            c1.metric('Records', f'{len(result):,}')
            c2.metric('Flagged ransomware', f"{(result.Prediction == 'Ransomware').sum():,}")
            c3.metric('Predicted benign', f"{(result.Prediction == 'Benign').sum():,}")
            if result['Unseen machine code'].any():
                st.warning('Some rows use unseen machine codes; these are marked in the results.')
            st.dataframe(result.head(1000), hide_index=True, width='stretch')
            st.caption('Preview shows up to 1,000 records; the download contains all results.')
            # Prevent spreadsheet formula interpretation in untrusted text columns.
            export = result.copy()
            for c in export.select_dtypes(include=['object', 'string']).columns:
                export[c] = export[c].map(lambda v: "'" + v if isinstance(v, str) and v.lstrip().startswith(('=', '+', '-', '@')) else v)
            st.download_button('Download predictions', export.to_csv(index=False), 'predictions.csv', 'text/csv', type='primary')
        except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as exc:
            st.error(f'Cannot analyze this CSV: {exc}')

with performance:
    st.subheader('Your saved notebook model')
    if summary:
        st.write('Data source: ' + bundle['evaluation'].get('data_source', 'Not recorded'))
        st.write('Selected parameters:', bundle['evaluation'].get('best_params', {}))
        c1, c2, c3 = st.columns(3)
        c1.metric('Training records', f"{bundle['train_rows']:,}")
        c2.metric('Test records', f"{bundle['test_rows']:,}")
        c3.metric('ROC AUC', f"{summary['ROC AUC']:.4f}")
        st.dataframe(pd.DataFrame(summary['confusion_matrix'], index=['Actual ransomware', 'Actual benign'], columns=['Predicted ransomware', 'Predicted benign']), width='stretch')
        st.warning('The notebook fits its scaler before splitting. Test results may be optimistic. This UI preserves that preprocessing to match the saved model.')
    else:
        st.info('No exported evaluation data. The UI does not retrain or invent scores.')
    coefficients = pd.Series(bundle['classifier'].coef_[0], index=bundle['columns'])
    top = coefficients.reindex(coefficients.abs().nlargest(12).index).sort_values()
    st.bar_chart(top, horizontal=True, color='#56d4b2')
    st.caption('Positive coefficients favor benign; negative coefficients favor ransomware.')

with about:
    st.subheader('Saved-model inference')
    st.markdown("""This app loads the notebook's saved classifier, scaler, and feature-column list. It applies the same four derived features, aligns the one-hot Machine columns, and transforms values with the saved scaler. No fitting or hyperparameter search takes place here.

At threshold 0.50, labels come directly from the classifier's predict method. Changing the threshold deliberately changes the decision rule.

The included CSV provides UI examples only. Export evaluation.json to record the notebook's actual data source and test results. The uploaded notebook's stored outputs used synthetic data.

Labels: **0 = ransomware; 1 = benign**. This research app classifies extracted features, not executable files.""")
