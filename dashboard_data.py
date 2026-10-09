"""Reproducible data and Plotly figures for the saved ransomware model.

All evaluation charts use persisted probabilities from the notebook's held-out set.
The dataset hold-out order is recreated only to display the corresponding raw PE
records: notebook cleaning + stratified 80/20 split with random_state=42.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from sklearn.metrics import precision_recall_curve, roc_curve
from sklearn.model_selection import train_test_split

from model import FEATURES

ROOT = Path(__file__).resolve().parent
PURPLE = "#7358e7"
INK = "#17243b"
MUTED = "#718096"
TEAL = "#16a99d"
CORAL = "#ef7e84"
GRID = "#edf0f6"


def read_dataset() -> pd.DataFrame:
    """Read the same CSV packaged with the original project."""
    raw = pd.read_csv(ROOT / "data_file.csv")
    needed = {"Benign", "md5Hash", *FEATURES}
    missing = needed - set(raw.columns)
    if missing:
        raise ValueError(f"Missing dataset columns: {', '.join(sorted(missing))}")
    return raw


def cleaned_dataset(raw: pd.DataFrame) -> pd.DataFrame:
    """Match notebook cells 9/17, including deduplication order."""
    return raw.drop_duplicates().drop_duplicates(subset="md5Hash", keep="first").reset_index(drop=True)


def reconstruction(raw: pd.DataFrame, bundle: dict) -> pd.DataFrame:
    """Recreate stored held-out rows and fail closed on inconsistent inputs.

    This avoids presenting samples as 'unseen test data' unless the labels of
    every recreated sample match the saved evaluation file in exactly its order.
    """
    cleaned = cleaned_dataset(raw)
    _, indices = train_test_split(
        np.arange(len(cleaned)), test_size=0.20, random_state=42,
        stratify=cleaned["Benign"],
    )
    holdout = cleaned.iloc[indices].copy().reset_index(drop=True)
    if len(holdout) != len(bundle["test_y"]) or not np.array_equal(
        holdout["Benign"].to_numpy(), bundle["test_y"].to_numpy()
    ):
        raise ValueError("Dataset does not match the saved evaluation split; sample testing is unavailable.")
    return holdout


def plot_style(fig: go.Figure, height: int = 340) -> go.Figure:
    fig.update_layout(
        height=height, autosize=True, margin=dict(l=10, r=15, t=20, b=35),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, Arial, sans-serif", color=INK, size=12),
        hoverlabel=dict(bgcolor="#fff", bordercolor=GRID, font_color=INK),
        showlegend=False,
    )
    return fig


def class_donut(raw: pd.DataFrame) -> go.Figure:
    counts = raw["Benign"].value_counts()
    fig = go.Figure(go.Pie(
        labels=["Ransomware", "Benign"],
        values=[int(counts.get(0, 0)), int(counts.get(1, 0))],
        marker=dict(colors=[PURPLE, "#52c7b9"], line=dict(color="white", width=5)),
        hole=0.72, textinfo="none",
        hovertemplate="<b>%{label}</b><br>%{value:,} files (%{percent})<extra></extra>",
        sort=False, direction="clockwise",
    ))
    plot_style(fig, 290)
    fig.add_annotation(text=f"<b>{len(raw):,}</b><br><span style='font-size:11px;color:#718096'>Total records</span>",
                       showarrow=False, font=dict(size=22, color=INK))
    fig.update_layout(margin=dict(t=12, b=12, l=12, r=12))
    return fig


def confusion_heatmap(cm: list[list[int]]) -> go.Figure:
    """Rows are actual Ransomware/Benign; columns predicted Ransomware/Benign."""
    matrix = np.asarray(cm)
    # The four values are drawn explicitly, with tooltip semantics.
    categories = [["Correct detection", "Missed ransomware"],
                  ["False alarm", "Correct benign"]]
    fig = go.Figure(go.Heatmap(
        z=matrix, x=["Ransomware", "Benign"], y=["Ransomware", "Benign"],
        customdata=categories, colorscale=[[0, "#f4f0ff"], [.5, "#c1b2fb"], [1, "#7156e5"]],
        showscale=False, zmin=0, zmax=max(1, int(matrix.max())),
        xgap=7, ygap=7,
        hovertemplate="Actual %{y}<br>Predicted %{x}<br><b>%{z:,} files</b><extra></extra>",
    ))
    for row_i, actual in enumerate(["Ransomware", "Benign"]):
        for col_i, predicted in enumerate(["Ransomware", "Benign"]):
            count = int(matrix[row_i, col_i])
            fig.add_annotation(
                x=predicted, y=actual, showarrow=False, align="center",
                text=f"<b>{count:,}</b><br><span style='font-size:11px'>{categories[row_i][col_i]}</span>",
                font=dict(size=23, color="white" if count / max(matrix.max(),1) > .62 else INK),
            )
    plot_style(fig, 355)
    fig.update_yaxes(autorange="reversed", title_text="Actual label", side="left", tickfont=dict(size=12),
                     showgrid=False, zeroline=False)
    fig.update_xaxes(title_text="Predicted label", side="bottom", tickfont=dict(size=12),
                     showgrid=False, zeroline=False)
    fig.update_layout(margin=dict(l=15, r=10, t=10, b=48))
    return fig


def roc_plot(bundle: dict, threshold: float, cm: list[list[int]]) -> go.Figure:
    actual = (bundle["test_y"].to_numpy() == 0).astype(int)
    fpr, tpr, _ = roc_curve(actual, bundle["test_probability"])
    tp, fn = cm[0]
    fp, tn = cm[1]
    op_fpr = fp / (fp + tn) if fp + tn else 0
    op_tpr = tp / (tp + fn) if tp + fn else 0
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=fpr, y=tpr, name="Model ROC", mode="lines", fill="tozeroy",
        line=dict(color=PURPLE, width=3.5), fillcolor="rgba(115,88,231,.09)",
        hovertemplate="FPR %{x:.3f}<br>TPR %{y:.3f}<extra></extra>"
    ))
    fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="Random baseline",
                             line=dict(color="#a9b3c5", dash="dash", width=1.7), hoverinfo="skip"))
    fig.add_trace(go.Scatter(
        x=[op_fpr], y=[op_tpr], mode="markers", name="Selected threshold",
        marker=dict(color=CORAL, size=13, line=dict(color="white", width=3)),
        hovertemplate=f"Threshold {threshold:.2f}<br>FPR %{{x:.3f}}<br>TPR %{{y:.3f}}<extra></extra>",
    ))
    plot_style(fig, 355)
    fig.update_xaxes(title="False positive rate", range=[0, 1], gridcolor=GRID, zeroline=False,
                     tickformat=".0%", dtick=.2)
    fig.update_yaxes(title="True positive rate", range=[0, 1.02], gridcolor=GRID, zeroline=False,
                     tickformat=".0%", dtick=.2)
    fig.update_layout(margin=dict(l=18, r=15, t=10, b=47))
    return fig


def importance_plot(bundle: dict, n: int = 12) -> go.Figure:
    """Coefficient signs correspond to Benign=1, NOT ransomware=0."""
    weights = pd.Series(bundle["classifier"].coef_[0], index=bundle["columns"])
    selected = weights.loc[weights.abs().nlargest(n).index].sort_values()
    display = [x.replace("Machine_", "Machine code: ") for x in selected.index]
    fig = go.Figure(go.Bar(
        x=selected.to_numpy(), y=display, orientation="h",
        marker=dict(color=[TEAL if x > 0 else CORAL for x in selected], line=dict(width=0)),
        hovertemplate="<b>%{y}</b><br>Coefficient: %{x:.3f}<extra></extra>"
    ))
    plot_style(fig, max(350, n * 32 + 65))
    fig.update_xaxes(title="Model coefficient (signed)", gridcolor=GRID, zeroline=True,
                     zerolinecolor="#b9c3d3", zerolinewidth=1)
    fig.update_yaxes(tickfont=dict(size=11), automargin=True)
    fig.update_layout(margin=dict(l=10, r=15, t=10, b=45))
    return fig


def precision_recall_plot(bundle: dict) -> go.Figure:
    actual = (bundle["test_y"].to_numpy() == 0).astype(int)
    precision, recall, _ = precision_recall_curve(actual, bundle["test_probability"])
    fig = go.Figure(go.Scatter(
        x=recall, y=precision, mode="lines", line=dict(color=TEAL, width=3),
        fill="tozeroy", fillcolor="rgba(22,169,157,.08)",
        hovertemplate="Recall %{x:.3f}<br>Precision %{y:.3f}<extra></extra>"
    ))
    plot_style(fig, 310)
    fig.update_xaxes(title="Recall (ransomware)", range=[0, 1], gridcolor=GRID, tickformat=".0%")
    fig.update_yaxes(title="Precision (ransomware)", range=[0, 1.02], gridcolor=GRID, tickformat=".0%")
    return fig


def sample_choices(bundle: dict, limit_per_group: int = 20) -> dict[str, list[int]]:
    """Actual held-out sample offsets, grouped by observed correct/error outcomes."""
    actual = bundle["test_y"].to_numpy() == 0
    predicted = bundle["test_probability"] > .5
    groups = {
        "Detected ransomware · true positive": np.flatnonzero(actual & predicted),
        "Benign file · true negative": np.flatnonzero(~actual & ~predicted),
        "False alarm · false positive": np.flatnonzero(~actual & predicted),
        "Missed ransomware · false negative": np.flatnonzero(actual & ~predicted),
    }
    return {k: a[np.linspace(0, len(a) - 1, min(limit_per_group, len(a)), dtype=int)].tolist()
            for k, a in groups.items() if len(a)}
