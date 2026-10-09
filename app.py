"""Streamlit dashboard for the saved ransomware Logistic Regression classifier."""
from __future__ import annotations

import hashlib
import json
from html import escape
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

from dashboard_data import (
    class_donut,
    cleaned_dataset,
    confusion_heatmap,
    importance_plot,
    precision_recall_plot,
    read_dataset,
    reconstruction,
    roc_plot,
    sample_choices,
)
from dashboard_styles import STYLE
from model import FEATURES, load_saved_model, metrics, predict
from pe_extractor import MAX_PE_BYTES, PEFormatError, extract_pe_features

ROOT = Path(__file__).resolve().parent
DEFAULT_THRESHOLD = 0.5

st.set_page_config(page_title="RansomGuard", page_icon="🛡️", layout="wide")
st.markdown(STYLE, unsafe_allow_html=True)


@st.cache_resource(show_spinner=False)
def get_model(version: tuple[int, ...]) -> dict:
    return load_saved_model()


@st.cache_data(show_spinner=False)
def get_dataset(version: int) -> pd.DataFrame:
    return read_dataset()


def safe_text(value: object) -> str:
    return escape(str(value), quote=True)


def page_title(title: str) -> None:
    st.markdown(f'<div class="page-heading"><h1>{safe_text(title)}</h1></div>', unsafe_allow_html=True)


def section_title(title: str) -> None:
    st.markdown(f'<h2 class="section-title">{safe_text(title)}</h2>', unsafe_allow_html=True)


def panel_title(title: str) -> None:
    st.markdown(f'<h3 class="panel-title">{safe_text(title)}</h3>', unsafe_allow_html=True)


def stat(label: str, value: str) -> None:
    st.markdown(
        '<div class="stat-card">'
        f'<div class="stat-label">{safe_text(label)}</div>'
        f'<div class="stat-value">{safe_text(value)}</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def stats(items: list[tuple[str, str]]) -> None:
    for col, (label, value) in zip(st.columns(len(items), gap="medium"), items):
        with col:
            stat(label, value)


def detail_row(label: str, value: str) -> None:
    st.markdown(
        f'<div class="detail-row"><span>{safe_text(label)}</span>'
        f'<strong>{safe_text(value)}</strong></div>',
        unsafe_allow_html=True,
    )


def render_prediction(result: pd.Series, filename: str, actual: str | None = None) -> None:
    is_ransomware = str(result["Prediction"]) == "Ransomware"
    probability = float(result["Ransomware probability"])
    name = "Ransomware" if is_ransomware else "Benign"
    color_class = "threat" if is_ransomware else "clean"
    st.markdown(
        f'<div class="prediction {color_class}">'
        '<div class="prediction-label">Prediction</div>'
        f'<div class="prediction-name">{name}</div>'
        f'<div class="prediction-file">{safe_text(filename)}</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    if actual is not None:
        st.markdown(f'**Actual label:** {safe_text(actual)}')
    col1, col2 = st.columns(2, gap="medium")
    col1.metric("Ransomware probability", f"{probability:.2%}")
    col2.metric("Benign probability", f"{1 - probability:.2%}")
    if bool(result["Unseen machine code"]):
        st.warning("The machine code was not included in the training data.")


try:
    model_files = ROOT / "artifacts"
    versions = tuple(
        path.stat().st_mtime_ns for path in sorted(model_files.glob("*")) if path.is_file()
    )
    bundle = get_model(versions)
except (OSError, ValueError, TypeError, KeyError, EOFError, ImportError) as exc:
    st.error(f"Could not load the saved model: {exc}")
    st.stop()

try:
    raw = get_dataset((ROOT / "data_file.csv").stat().st_mtime_ns)
    dataset_error = None
except (OSError, ValueError, pd.errors.ParserError) as exc:
    raw = None
    dataset_error = str(exc)

with st.sidebar:
    st.markdown(
        '<div class="brand"><span class="brand-mark">R</span>'
        '<span>RansomGuard</span></div>',
        unsafe_allow_html=True,
    )
    page = st.radio(
        "Navigation",
        ["Overview", "Model performance", "Sample predictions", "File scanner", "Manual prediction"],
        label_visibility="collapsed",
    )

if page == "Overview":
    page_title("Overview")
    if raw is None:
        st.error(f"Could not load data_file.csv: {dataset_error}")
        st.stop()

    scores = metrics(bundle, DEFAULT_THRESHOLD)
    ransomware_count = int((raw["Benign"] == 0).sum())
    benign_count = int((raw["Benign"] == 1).sum())
    stats([
        ("Dataset samples", f"{len(raw):,}"),
        ("Ransomware", f"{ransomware_count:,}"),
        ("Accuracy", f"{scores['Accuracy']:.2%}"),
        ("ROC-AUC", f"{scores['ROC AUC']:.4f}"),
    ])

    section_title("Dataset overview")
    left, right = st.columns([1, 1], gap="medium")
    with left:
        with st.container(border=True):
            panel_title("Class distribution")
            st.plotly_chart(class_donut(raw), use_container_width=True, config={"displayModeBar": False})
            st.markdown(
                f'<div class="legend"><span><i class="key-purple"></i>Ransomware &nbsp; {ransomware_count:,}</span>'
                f'<span><i class="key-teal"></i>Benign &nbsp; {benign_count:,}</span></div>',
                unsafe_allow_html=True,
            )
    with right:
        with st.container(border=True):
            panel_title("Model details")
            cleaned = cleaned_dataset(raw)
            for label, value in [
                ("Algorithm", "Logistic Regression"),
                ("Features", str(len(bundle["columns"]))),
                ("Training samples", f"{bundle['train_rows']:,}"),
                ("Test samples", f"{bundle['test_rows']:,}"),
                ("Unique dataset records", f"{len(cleaned):,}"),
                ("Classification", "Ransomware / Benign"),
            ]:
                detail_row(label, value)

    section_title("Test-set results")
    stats([
        ("Precision", f"{scores['Ransomware precision']:.2%}"),
        ("Recall", f"{scores['Ransomware recall']:.2%}"),
        ("F1 score", f"{scores['Ransomware F1']:.2%}"),
        ("Test samples", f"{bundle['test_rows']:,}"),
    ])

elif page == "Model performance":
    page_title("Model performance")
    if not bundle.get("evaluation"):
        st.error("Missing saved evaluation results in artifacts/evaluation.json.")
        st.stop()

    threshold = st.slider(
        "Decision threshold", min_value=0.05, max_value=0.95,
        value=DEFAULT_THRESHOLD, step=0.01,
    )
    scores = metrics(bundle, threshold)
    stats([
        ("Accuracy", f"{scores['Accuracy']:.2%}"),
        ("Precision", f"{scores['Ransomware precision']:.2%}"),
        ("Recall", f"{scores['Ransomware recall']:.2%}"),
        ("F1 score", f"{scores['Ransomware F1']:.2%}"),
    ])

    section_title("Evaluation charts")
    left, right = st.columns(2, gap="medium")
    with left:
        with st.container(border=True):
            panel_title("Confusion matrix")
            st.plotly_chart(
                confusion_heatmap(scores["confusion_matrix"]),
                use_container_width=True, config={"displayModeBar": False},
            )
    with right:
        with st.container(border=True):
            panel_title(f"ROC curve  ·  AUC {scores['ROC AUC']:.4f}")
            st.plotly_chart(
                roc_plot(bundle, threshold, scores["confusion_matrix"]),
                use_container_width=True, config={"displayModeBar": False},
            )

    tp, fn = scores["confusion_matrix"][0]
    fp, tn = scores["confusion_matrix"][1]
    stats([
        ("True positives", f"{tp:,}"),
        ("False negatives", f"{fn:,}"),
        ("False positives", f"{fp:,}"),
        ("True negatives", f"{tn:,}"),
    ])

    section_title("Feature importance")
    n_features = st.select_slider("Features to display", options=[8, 12, 16, 24], value=12)
    with st.container(border=True):
        st.plotly_chart(importance_plot(bundle, n_features), use_container_width=True,
                        config={"displayModeBar": False})
        st.markdown(
            '<div class="legend"><span><i class="key-teal"></i>Benign</span>'
            '<span><i class="key-coral"></i>Ransomware</span></div>',
            unsafe_allow_html=True,
        )

    section_title("Precision–recall curve")
    with st.container(border=True):
        st.plotly_chart(precision_recall_plot(bundle), use_container_width=True,
                        config={"displayModeBar": False})

    with st.expander("Evaluation notes"):
        st.write(
            "Charts are based on the test predictions saved from the training notebook. "
            "The notebook fitted its scaler before splitting the dataset, so the test "
            "scores may be optimistic. Feature importance uses Logistic Regression "
            "coefficients, not Random Forest importance."
        )

elif page == "Sample predictions":
    page_title("Sample predictions")
    if raw is None:
        st.error(f"Could not load data_file.csv: {dataset_error}")
        st.stop()

    try:
        examples = reconstruction(raw, bundle)
        groups = sample_choices(bundle)
    except (ValueError, KeyError) as exc:
        st.error(f"Could not reconstruct the original test split: {exc}")
        st.stop()

    left, right = st.columns([1, 1], gap="medium")
    with left:
        with st.container(border=True):
            panel_title("Test a dataset sample")
            category = st.selectbox("Category", list(groups))
            sample_index = st.selectbox(
                "Sample", groups[category],
                format_func=lambda idx: f"Sample {idx + 1:,}",
            )
            record = examples.iloc[sample_index]
            example = pd.DataFrame([{f: record[f] for f in FEATURES}])
            prediction = predict(bundle, example, DEFAULT_THRESHOLD).iloc[0]
            if not np.isclose(
                float(prediction["Ransomware probability"]),
                float(bundle["test_probability"][sample_index]), atol=1e-8,
            ):
                st.error("This sample does not match the stored test predictions.")
                st.stop()

            actual = "Benign" if int(record["Benign"]) == 1 else "Ransomware"
            filename = str(record.get("FileName", f"Sample {sample_index + 1}"))
            render_prediction(prediction, filename, actual=actual)
            if str(prediction["Prediction"]) != actual:
                st.warning("Incorrect classification")
            st.download_button(
                "Download sample CSV", pd.DataFrame([record]).to_csv(index=False),
                file_name=f"sample_{sample_index + 1}.csv", mime="text/csv",
            )
    with right:
        with st.container(border=True):
            panel_title("PE features")
            st.dataframe(
                pd.DataFrame({"Feature": FEATURES, "Value": [int(record[f]) for f in FEATURES]}),
                hide_index=True, use_container_width=True, height=520,
            )

    section_title("Edit sample")
    with st.form(f"sample_edit_{sample_index}"):
        input_columns = st.columns(3, gap="medium")
        edited = {}
        for position, feature in enumerate(FEATURES):
            edited[feature] = input_columns[position % 3].number_input(
                feature, min_value=0, max_value=2**53 - 1,
                value=int(record[feature]), step=1,
                key=f"sample_{sample_index}_{feature}",
            )
        run = st.form_submit_button("Predict", type="primary")
    if run:
        try:
            updated = predict(bundle, pd.DataFrame([edited]), DEFAULT_THRESHOLD).iloc[0]
            render_prediction(updated, "Edited sample")
        except (TypeError, ValueError) as exc:
            st.error(f"Prediction failed: {exc}")

elif page == "File scanner":
    page_title("File scanner")
    left, right = st.columns([1.5, 1], gap="medium")
    with left:
        with st.container(border=True):
            panel_title("Analyze PE file")
            uploaded = st.file_uploader("Windows executable", type=["exe", "dll"])
            scan = st.button("Scan file", type="primary", disabled=uploaded is None,
                             use_container_width=True)
    with right:
        with st.container(border=True):
            panel_title("Scanner details")
            for label, value in [
                ("File types", "EXE, DLL"),
                ("Maximum size", "20 MB"),
                ("Analysis", "Static PE headers"),
                ("Model", "Logistic Regression"),
            ]:
                detail_row(label, value)

    # Use the file contents, not implementation-specific UploadedFile properties,
    # to distinguish two uploads with the same name and size.
    fingerprint = None
    if uploaded is not None:
        fingerprint = (uploaded.name, hashlib.sha256(uploaded.getvalue()).hexdigest())
    if st.session_state.get("uploaded_fingerprint") != fingerprint:
        st.session_state.pop("scan_result", None)
        st.session_state["uploaded_fingerprint"] = fingerprint

    if scan and uploaded is not None:
        st.session_state.pop("scan_result", None)
        try:
            if uploaded.size > MAX_PE_BYTES:
                raise PEFormatError("File exceeds the 20 MB limit.")
            extracted_info = extract_pe_features(uploaded.getvalue())
            features = pd.DataFrame([extracted_info.features], columns=FEATURES)
            outcome = predict(bundle, features, DEFAULT_THRESHOLD).iloc[0]
            st.session_state["scan_result"] = (uploaded.name, extracted_info, features, outcome)
        except (PEFormatError, ValueError, TypeError) as exc:
            st.error(f"Scan failed: {exc}")

    if "scan_result" in st.session_state:
        filename, info, features, outcome = st.session_state["scan_result"]
        section_title("Scan result")
        render_prediction(outcome, filename)
        first, second = st.columns(2)
        first.metric("PE format", info.pe_kind)
        second.metric("File size", f"{info.size_bytes / 1024:.1f} KB")
        if info.is_dll != filename.lower().endswith(".dll"):
            st.warning("The file extension differs from the PE header type.")
        with st.expander("File details"):
            st.code(info.sha256, language=None)
            st.dataframe(features.T.rename(columns={0: "Value"}), use_container_width=True)
            st.write(info.wallet_scan_note)
        report = {
            "filename": filename,
            "sha256": info.sha256,
            "prediction": str(outcome["Prediction"]),
            "ransomware_probability": float(outcome["Ransomware probability"]),
            "features": info.features,
            "threshold": DEFAULT_THRESHOLD,
        }
        st.download_button(
            "Download JSON report", json.dumps(report, indent=2),
            file_name="scan_report.json", mime="application/json",
        )
    with st.expander("Scanner limitations"):
        st.write(
            "This is an experimental static-feature classifier, not antivirus software. "
            "It does not run the uploaded file. A benign result does not establish that "
            "the file is safe."
        )

elif page == "Manual prediction":
    page_title("Manual prediction")
    profiles = {"Blank input": pd.Series({feature: 0 for feature in FEATURES})}
    if raw is not None:
        cleaned = cleaned_dataset(raw)
        profiles = {
            "Benign sample": cleaned.loc[cleaned["Benign"] == 1, FEATURES].iloc[0],
            "Ransomware sample": cleaned.loc[cleaned["Benign"] == 0, FEATURES].iloc[0],
            **profiles,
        }
    chosen = st.selectbox("Input preset", list(profiles))
    defaults = profiles[chosen]
    with st.form(f"manual_{chosen}"):
        columns = st.columns(3, gap="medium")
        values = {}
        for index, feature in enumerate(FEATURES):
            values[feature] = columns[index % 3].number_input(
                feature, min_value=0, max_value=2**53 - 1,
                value=int(defaults[feature]), step=1,
                key=f"manual_{chosen}_{feature}",
            )
        submitted = st.form_submit_button("Predict", type="primary")
    if submitted:
        try:
            response = predict(bundle, pd.DataFrame([values]), DEFAULT_THRESHOLD).iloc[0]
            render_prediction(response, "Manual input")
        except (ValueError, TypeError) as exc:
            st.error(f"Prediction failed: {exc}")
