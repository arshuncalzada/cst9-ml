"""RansomGuard | polished Streamlit dashboard for the USER'S trained PE model.

Run: streamlit run app.py
No model training or fabricated performance data occurs at dashboard runtime.
"""
from __future__ import annotations

import json
from html import escape
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

from dashboard_data import (
    class_donut, cleaned_dataset, confusion_heatmap, importance_plot,
    precision_recall_plot, read_dataset, reconstruction, roc_plot, sample_choices,
)
from dashboard_styles import STYLE
from model import FEATURES, load_saved_model, metrics, predict
from pe_extractor import MAX_PE_BYTES, PEFormatError, extract_pe_features

ROOT = Path(__file__).resolve().parent
THRESHOLD = 0.50

st.set_page_config(
    page_title="RansomGuard • Ransomware Intelligence",
    page_icon="🛡️", layout="wide", initial_sidebar_state="expanded",
)
st.markdown(STYLE, unsafe_allow_html=True)


@st.cache_resource(show_spinner="Loading your trained model…")
def cached_model(version: tuple[int, ...]) -> dict:
    return load_saved_model()


@st.cache_data(show_spinner=False)
def cached_dataset(version: int) -> pd.DataFrame:
    return read_dataset()


def html(value: object) -> str:
    return escape(str(value), quote=True)


def heading(title: str, subtitle: str = "") -> None:
    st.markdown(
        f'<div class="section-h"><h2>{html(title)}</h2><span>{html(subtitle)}</span></div>',
        unsafe_allow_html=True,
    )


def hero(kicker: str, title: str, description: str, tags: list[str]) -> None:
    pills = "".join(
        f'<span class="pill{(" good" if i == 0 else "")}">{html(label)}</span>'
        for i, label in enumerate(tags)
    )
    st.markdown(
        '<div class="hero">'
        f'<div class="hero-kicker">{html(kicker)}</div>'
        f'<h1>{html(title)}</h1><p>{html(description)}</p>'
        f'<div class="hero-tags">{pills}</div></div>',
        unsafe_allow_html=True,
    )


def kpi(label: str, value: str, foot: str, glyph: str) -> None:
    st.markdown(
        f'<div class="kpi-card"><div class="kpi-top"><span class="kpi-label">{html(label)}</span>'
        f'<span class="kpi-icon">{html(glyph)}</span></div>'
        f'<div class="kpi-value">{html(value)}</div><div class="kpi-foot">{html(foot)}</div></div>',
        unsafe_allow_html=True,
    )


def show_kpis(items: list[tuple[str, str, str, str]]) -> None:
    for col, (label, value, foot, icon) in zip(st.columns(len(items), gap="medium"), items):
        with col:
            kpi(label, value, foot, icon)


def panel(title: str, caption: str = "") -> None:
    st.markdown(
        f'<h3 style="font-size:16px;font-weight:800;margin:1px 0 3px">{html(title)}</h3>'
        f'<p class="small-text" style="margin:0 0 12px">{html(caption)}</p>',
        unsafe_allow_html=True,
    )


def output_card(outcome: pd.Series, filename: str, *, actual_label: str | None = None) -> None:
    flagged = str(outcome["Prediction"]) == "Ransomware"
    score = float(outcome["Ransomware probability"])
    text = "Ransomware indicated" if flagged else "Predicted benign"
    desc = f"{filename} · Ransomware probability {score:.2%}"
    st.markdown(
        f'<div class="result-card{(" flag" if flagged else "")}">'
        '<div class="result-mini">Trained model prediction</div>'
        f'<div class="result-main">{text}</div>'
        f'<div class="result-text">{html(desc)}</div></div>',
        unsafe_allow_html=True,
    )
    if actual_label is not None:
        st.caption(f"Dataset ground truth: **{actual_label}**. This is a benchmark label, not a guarantee of detection.")
    left, right = st.columns([1, 1])
    left.metric("Ransomware probability", f"{score:.2%}")
    right.metric("Benign probability", f"{1 - score:.2%}")
    st.progress(max(0., min(1., score)))
    if bool(outcome["Unseen machine code"]):
        st.warning("This machine/processor code was not observed during training. Treat the result with extra caution.")


# Keep the saved artifact provenance and versioned caches.
try:
    artifact_dir = ROOT / "artifacts"
    artifact_versions = tuple(p.stat().st_mtime_ns for p in sorted(artifact_dir.glob("*")) if p.is_file())
    bundle = cached_model(artifact_versions)
except (OSError, ValueError, TypeError, KeyError, EOFError) as exc:
    st.error(f"The saved model could not be loaded: {exc}")
    st.info("Restore the model, scaler and feature-columns .joblib files to the artifacts/ directory.")
    st.stop()

try:
    raw = cached_dataset((ROOT / "data_file.csv").stat().st_mtime_ns)
    data_error = None
except (OSError, ValueError, pd.errors.ParserError) as exc:
    raw = None
    data_error = str(exc)

with st.sidebar:
    st.markdown(
        '<div class="brandmark"><div class="brand-icon">◇</div>'
        '<div><div class="brand-text">RansomGuard</div>'
        '<div class="brand-sub">DETECTION STUDIO</div></div></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="nav-label">WORKSPACE</div>', unsafe_allow_html=True)
    navigation = st.radio(
        "Workspace", [
            "◈  Overview", "▦  Model performance", "◉  Sample predictions",
            "⬡  File scanner", "▤  Manual analysis",
        ], label_visibility="collapsed", key="navigation",
    )
    st.markdown(
        '<div class="side-note"><strong>● &nbsp; Model loaded</strong><br>'
        'Logistic Regression · PE static features<br>'
        'Notebook-trained · No online retraining</div>',
        unsafe_allow_html=True,
    )
    st.caption("Academic research prototype  •  v2.0")

page = navigation.split("  ", 1)[-1]

if page == "Overview":
    hero(
        "Ransomware intelligence / Overview", "Know your model. Understand the risk.",
        "A research-grade command center built around your own Windows PE dataset "
        "and notebook-trained Logistic Regression classifier.",
        ["● Trained model loaded", "Dataset-backed analytics", "Static PE analysis"],
    )
    if raw is None:
        st.error(f"Could not read the bundled dataset: {data_error}")
        st.stop()
    overview_metrics = metrics(bundle, THRESHOLD)
    malware_count = int((raw["Benign"] == 0).sum())
    benign_count = int((raw["Benign"] == 1).sum())
    show_kpis([
        ("Dataset records", f"{len(raw):,}", "Original provided CSV", "▣"),
        ("Ransomware samples", f"{malware_count:,}", "Target Benign = 0", "◈"),
        ("Test accuracy", f"{overview_metrics['Accuracy']:.2%}", "Saved notebook hold-out", "◎"),
        ("ROC–AUC", f"{overview_metrics['ROC AUC']:.3f}", "Positive class: ransomware", "↗"),
    ])

    heading("Dataset at a glance", "Live counts from your CSV")
    left, right = st.columns([1.06, .94], gap="medium")
    with left:
        with st.container(border=True):
            panel("Class distribution", "Original file labels from data_file.csv")
            st.plotly_chart(class_donut(raw), use_container_width=True, config={"displayModeBar": False})
            st.markdown(
                '<div class="swatch-line">'
                f'<span><i class="swatch" style="background:#7358e7"></i>Ransomware &nbsp; {malware_count:,}</span>'
                f'<span><i class="swatch" style="background:#52c7b9"></i>Benign &nbsp; {benign_count:,}</span></div>',
                unsafe_allow_html=True,
            )
    with right:
        with st.container(border=True):
            panel("Training snapshot", "Reconstructed from the saved notebook metadata")
            clean = cleaned_dataset(raw)
            rows = [
                ("Classifier", "Logistic Regression"),
                ("Task", "Binary classification"),
                ("Dataset size", f"{len(raw):,} rows"),
                ("After duplicate removal", f"{len(clean):,} rows"),
                ("Training split", f"{int(bundle['train_rows']):,} · 80%"),
                ("Evaluation split", f"{int(bundle['test_rows']):,} · 20%"),
                ("Model inputs", f"{len(bundle['columns'])} encoded / engineered"),
                ("Missing cells", f"{int(raw.isna().sum().sum()):,}"),
            ]
            for label, value in rows:
                st.markdown(
                    f'<div class="stat-row"><span>{html(label)}</span><strong>{html(value)}</strong></div>',
                    unsafe_allow_html=True,
                )
    heading("Inside the detection pipeline", "How your model works")
    with st.container(border=True):
        steps = st.columns(4, gap="medium")
        blocks = [
            ("01 · INPUT", "PE header features", "15 raw characteristics extracted from the file or selected from your dataset."),
            ("02 · PREPARE", "Engineer & encode", "Four derived fields plus one-hot encoding of the Machine architecture."),
            ("03 · TRANSFORM", "Standardize values", "Reuse the StandardScaler saved with your original notebook."),
            ("04 · DECIDE", "Classify risk", "Logistic Regression produces benign and ransomware probabilities."),
        ]
        for col, (number, title, desc) in zip(steps, blocks):
            with col:
                st.markdown(
                    f'<div class="crumb">{html(number)}</div>'
                    f'<h3 style="font-size:16px;margin:0 0 8px;font-weight:800">{html(title)}</h3>'
                    f'<p class="small-text">{html(desc)}</p>',
                    unsafe_allow_html=True,
                )
    st.markdown(
        '<div class="insight"><strong>Evaluation transparency.</strong> '
        'The notebook standardized data before splitting it into training and test sets. '
        'Reported test results may therefore be slightly optimistic. This model is a research '
        'prototype, not a certified malware scanner.</div>', unsafe_allow_html=True,
    )

elif page == "Model performance":
    hero(
        "Evaluation / Test-set results", "Model performance, decoded.",
        "Explore the exact predictions saved by your Jupyter notebook. Adjust the decision "
        "threshold to examine false alarms, missed ransomware, and classification trade-offs.",
        ["Saved test predictions", "12,497 held-out records", "Actual model coefficients"],
    )
    if not bundle.get("evaluation"):
        st.error("No evaluation.json exists. Export it using your completed training notebook.")
        st.stop()
    slider_col, explanation_col = st.columns([1, 2], gap="large")
    with slider_col:
        threshold = st.slider("Ransomware decision threshold", min_value=0.05,
                              max_value=0.95, value=0.50, step=0.01, key="eval_threshold")
    with explanation_col:
        st.caption("A lower threshold flags more files as ransomware. A higher threshold reduces "
                   "alerts but can miss more ransomware. This changes displayed decisions, not model weights.")
    summary = metrics(bundle, threshold)
    show_kpis([
        ("Accuracy", f"{summary['Accuracy']:.2%}", "Correct classifications", "◎"),
        ("Precision", f"{summary['Ransomware precision']:.2%}", "Ransomware alerts correct", "◉"),
        ("Recall", f"{summary['Ransomware recall']:.2%}", "Ransomware samples caught", "↗"),
        ("F1 score", f"{summary['Ransomware F1']:.2%}", "Precision–recall balance", "✦"),
    ])

    heading("Classification outcomes", "Based on the saved hold-out labels and probabilities")
    left, right = st.columns(2, gap="medium")
    with left:
        with st.container(border=True):
            panel("Confusion matrix", "Rows = true label · Columns = model decision")
            st.plotly_chart(confusion_heatmap(summary["confusion_matrix"]), use_container_width=True,
                            config={"displayModeBar": False})
    with right:
        with st.container(border=True):
            panel("ROC curve", f"Area under curve = {summary['ROC AUC']:.4f} · Orange point = threshold {threshold:.2f}")
            st.plotly_chart(roc_plot(bundle, threshold, summary["confusion_matrix"]),
                            use_container_width=True, config={"displayModeBar": False})

    tp, fn = summary["confusion_matrix"][0]
    fp, tn = summary["confusion_matrix"][1]
    stat_cols = st.columns(4, gap="medium")
    for col, (k, n, hint) in zip(stat_cols, [
        ("True positives", tp, "Detected ransomware"),
        ("False negatives", fn, "Missed ransomware"),
        ("False positives", fp, "Benign flagged"),
        ("True negatives", tn, "Correct benign"),
    ]):
        with col:
            kpi(k, f"{n:,}", hint, "·")

    heading("What drives predictions?", "Logistic Regression · signed coefficients")
    first, second = st.columns([1.42, .58], gap="medium")
    with first:
        with st.container(border=True):
            panel("Feature importance", "Ranked by the magnitude of each saved, fitted model coefficient")
            top_n = st.select_slider("Display strongest features", options=[8, 12, 16, 24], value=12)
            st.plotly_chart(importance_plot(bundle, top_n), use_container_width=True,
                            config={"displayModeBar": False})
            st.markdown('<div class="swatch-line"><span><i class="swatch" style="background:#16a99d"></i>Positive → benign</span>'
                        '<span><i class="swatch" style="background:#ef7e84"></i>Negative → ransomware</span></div>',
                        unsafe_allow_html=True)
    with second:
        with st.container(border=True):
            panel("Interpreting the model", "Class 0 = ransomware · Class 1 = benign")
            st.markdown(
                '<div class="insight"><strong>Why coefficients, not RF importance?</strong><br>'
                'Your notebook trains Logistic Regression. Its real feature weights are the '
                'correct model-specific interpretation—not Random Forest Gini importance.</div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<p class="small-text">Larger absolute coefficients indicate stronger model '
                'influence on the log-odds scale. Numeric inputs were standardized. '
                'Correlated features can make weights unstable, and no coefficient establishes causation.</p>',
                unsafe_allow_html=True,
            )
            params = bundle["evaluation"].get("best_params", {})
            st.markdown(
                '<div class="stat-row"><span>Regularization</span><strong>L2</strong></div>'
                f'<div class="stat-row"><span>Selected C</span><strong>{html(params.get("C", "Not recorded"))}</strong></div>'
                '<div class="stat-row"><span>Saved default threshold</span><strong>0.50</strong></div>',
                unsafe_allow_html=True,
            )

    with st.expander("Additional evaluation: precision–recall curve and study limitations"):
        panel("Precision–recall curve", "Computed directly from persisted ransomware probabilities")
        st.plotly_chart(precision_recall_plot(bundle), use_container_width=True,
                        config={"displayModeBar": False})
        st.warning(
            "Methodology note: Notebook cell 13 fitted the scaler on the whole dataset before "
            "cell 17 created the train/test split. This causes preprocessing leakage. The saved "
            "hold-out scores are not a fully independent estimate, and no external real-file "
            "malware-detection accuracy has been established."
        )

elif page == "Sample predictions":
    hero(
        "Experiment / Hold-out samples", "Test real samples. See real predictions.",
        "Choose a file record from your original 20% evaluation split. Compare the model prediction "
        "to its dataset label or modify the PE values to explore what changes.",
        ["Real dataset examples", "Actual saved test split", "Editable feature inputs"],
    )
    if raw is None:
        st.error(f"Sample testing requires your data_file.csv: {data_error}")
        st.stop()
    try:
        test_records = reconstruction(raw, bundle)
        choices = sample_choices(bundle)
    except ValueError as exc:
        st.error(str(exc))
        st.stop()
    left, right = st.columns([1.04, .96], gap="medium")
    with left:
        with st.container(border=True):
            panel("Choose a saved test example", "Positive class: ransomware · Unseen 20% hold-out split")
            group = st.selectbox("Example category", list(choices.keys()))
            index = st.selectbox(
                "Test example", choices[group],
                format_func=lambda i: f"#{i + 1:,}  ·  {str(test_records.iloc[i].get('FileName','PE sample'))[:38]}",
            )
            record = test_records.iloc[index]
            frame = pd.DataFrame([{f: record[f] for f in FEATURES}])
            outcome = predict(bundle, frame, THRESHOLD).iloc[0]
            # Validate correspondence with the persisted probabilities, not just labels.
            if not np.isclose(float(outcome["Ransomware probability"]),
                              float(bundle["test_probability"][index]), atol=1e-8):
                st.error("The selected raw record disagrees with the saved evaluation. Sample prediction stopped.")
                st.stop()
            actual_label = "Benign" if int(record["Benign"]) == 1 else "Ransomware"
            output_card(outcome, str(record.get("FileName", "Dataset record")), actual_label=actual_label)
            correct = str(outcome["Prediction"]) == actual_label
            st.success("Prediction matches the dataset label.") if correct else st.warning(
                "Prediction differs from the dataset label. This is a genuine saved test-set error."
            )
            sample_csv = pd.DataFrame([record]).to_csv(index=False)
            st.download_button("Download selected sample (CSV)", sample_csv,
                               file_name=f"holdout_sample_{index + 1}.csv", mime="text/csv")
    with right:
        with st.container(border=True):
            panel("Raw PE attributes", "The 15 original inputs for the selected record")
            feature_display = pd.DataFrame({"Feature": FEATURES,
                                            "Value": [int(record[f]) for f in FEATURES]})
            st.dataframe(feature_display, hide_index=True, use_container_width=True, height=485)
            st.caption("Machine code is one-hot encoded; four derived indicators are created automatically.")

    heading("What-if prediction lab", "Modify the original record and submit")
    st.markdown('<p class="small-text">Values start from the selected real sample. After editing, '
                'the record is hypothetical and the dataset ground-truth label no longer applies.</p>',
                unsafe_allow_html=True)
    with st.form(f"sample_edit_{index}"):
        form_cols = st.columns(3, gap="medium")
        edited = {}
        for i, feature in enumerate(FEATURES):
            edited[feature] = form_cols[i % 3].number_input(
                feature, min_value=0, max_value=2**53 - 1,
                value=int(record[feature]), step=1, key=f"edit_{index}_{feature}",
            )
        submitted = st.form_submit_button("Run what-if prediction  →", type="primary")
    if submitted:
        try:
            modified = pd.DataFrame([edited], columns=FEATURES)
            new_outcome = predict(bundle, modified, THRESHOLD).iloc[0]
            output_card(new_outcome, "Modified feature record")
            st.info("This result is a what-if simulation based on your trained classifier. It is not a newly labeled file.")
        except (ValueError, TypeError) as exc:
            st.error(f"Could not evaluate the modified input: {exc}")

elif page == "File scanner":
    hero(
        "Detection / File analysis", "Analyze a Windows executable.",
        "Read static Portable Executable headers and estimate ransomware risk using the saved "
        "Logistic Regression model. Uploaded binaries are inspected, never executed.",
        ["Read-only analysis", "EXE & DLL files", "20 MiB maximum"],
    )
    left, right = st.columns([1.50, .80], gap="medium")
    with left:
        with st.container(border=True):
            panel("Upload a file", "Supported types: .exe, .dll · maximum 20 MiB")
            uploaded = st.file_uploader("Select an executable", type=["exe", "dll"], key="uploaded_pe")
            analyze = st.button("Analyze file  →", type="primary", disabled=uploaded is None,
                                use_container_width=True)
    with right:
        with st.container(border=True):
            panel("About this scan", "Non-executing PE header inspection")
            for label, val in [
                ("Classifier", "Logistic Regression"),
                ("Extracted inputs", "15 raw PE values"),
                ("Decision threshold", "50% ransomware"),
                ("Execution", "Never"),
            ]:
                st.markdown(
                    f'<div class="stat-row"><span>{html(label)}</span><strong>{html(val)}</strong></div>',
                    unsafe_allow_html=True,
                )
    current_id = (uploaded.name, uploaded.size, uploaded.file_id) if uploaded is not None else None
    if st.session_state.get("selected_file") != current_id:
        st.session_state.pop("scan_result", None)
        st.session_state["selected_file"] = current_id
    if analyze and uploaded is not None:
        st.session_state.pop("scan_result", None)
        try:
            if uploaded.size > MAX_PE_BYTES:
                raise PEFormatError("File exceeds the 20 MiB inspection limit.")
            with st.spinner("Reading PE headers…"):
                info = extract_pe_features(uploaded.getvalue())
                extracted = pd.DataFrame([info.features], columns=FEATURES)
                result = predict(bundle, extracted, THRESHOLD).iloc[0]
            st.session_state["scan_result"] = (uploaded.name, info, extracted, result)
        except (PEFormatError, ValueError, TypeError) as exc:
            st.error(f"Unable to inspect the selected file: {exc}")
    if "scan_result" in st.session_state:
        filename, info, extracted, result = st.session_state["scan_result"]
        heading("Scan result")
        output_card(result, filename)
        a, b = st.columns(2)
        a.metric("PE format", info.pe_kind)
        b.metric("File size", f"{info.size_bytes / 1024:.1f} KiB")
        if info.is_dll != filename.lower().endswith(".dll"):
            st.warning("File extension does not agree with the PE header's DLL flag.")
        with st.expander("Inspect extracted values and file fingerprint"):
            st.code(info.sha256, language=None)
            st.dataframe(extracted.T.rename(columns={0: "Extracted value"}), use_container_width=True)
            st.write(info.wallet_scan_note)
        report = {
            "filename": filename, "sha256": info.sha256,
            "prediction": str(result["Prediction"]),
            "ransomware_probability": float(result["Ransomware probability"]),
            "threshold": THRESHOLD, "features": info.features,
            "disclaimer": "Research prototype. A benign prediction does not guarantee safety. "
                          "Performance on uploaded binaries has not been independently validated.",
        }
        st.download_button("Download analysis report (JSON)", json.dumps(report, indent=2),
                           file_name="ransomware_scan_report.json", mime="application/json")
    else:
        st.markdown('<div class="insight"><strong>Ready when you are.</strong> '
                    'Choose a Windows PE file above to inspect its features. Do not treat '
                    'an apparent benign classification as proof that a file is safe.</div>',
                    unsafe_allow_html=True)

elif page == "Manual analysis":
    hero(
        "Detection / Manual inputs", "Build a custom feature record.",
        "Enter PE-header attributes or start from a real dataset example. The same saved "
        "preprocessing and logistic classifier are used as in the other sections.",
        ["15 PE attributes", "Same trained model", "Research predictions"],
    )
    if raw is not None:
        cleaned = cleaned_dataset(raw)
        benign_example = cleaned.loc[cleaned["Benign"] == 1, FEATURES].iloc[0]
        ransomware_example = cleaned.loc[cleaned["Benign"] == 0, FEATURES].iloc[0]
        presets = {
            "Dataset example · benign": benign_example,
            "Dataset example · ransomware": ransomware_example,
            "Empty form · zeros (out of distribution)": pd.Series({f: 0 for f in FEATURES}),
        }
    else:
        presets = {"Empty form · zeros (out of distribution)": pd.Series({f: 0 for f in FEATURES})}
    preset = st.selectbox("Start with a feature profile", list(presets.keys()))
    defaults = presets[preset]
    st.caption("Dataset profiles use individual real rows. Editing the values creates a hypothetical record.")
    with st.form(f"manual_{preset}"):
        input_cols = st.columns(3, gap="medium")
        values = {}
        for i, feature in enumerate(FEATURES):
            values[feature] = input_cols[i % 3].number_input(
                feature, min_value=0, max_value=2**53 - 1,
                value=int(defaults[feature]), step=1, key=f"manual_{preset}_{feature}",
            )
        submitted = st.form_submit_button("Classify this record  →", type="primary")
    if submitted:
        try:
            frame = pd.DataFrame([values], columns=FEATURES)
            output_card(predict(bundle, frame, THRESHOLD).iloc[0], "Manual feature entry")
            with st.expander("Submitted input features"):
                st.dataframe(frame.T.rename(columns={0: "Value"}), use_container_width=True)
        except (ValueError, TypeError) as exc:
            st.error(f"Could not classify the entered record: {exc}")
    if "zeros" in preset:
        st.warning("An all-zero PE record is not a realistic executable and its classification is unreliable.")

st.markdown(
    '<div class="footer">RansomGuard · Built on your original data_file.csv and notebook-exported artifacts. '
    'Binary labels: 0 = ransomware, 1 = benign. The app does not execute scanned files, '
    'retrain your model, or claim production-grade antivirus protection.</div>',
    unsafe_allow_html=True,
)
