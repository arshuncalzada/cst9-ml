"""Smoke/regression checks for the real-dataset dashboard analytics."""
import numpy as np

from dashboard_data import (
    class_donut, cleaned_dataset, confusion_heatmap, importance_plot,
    precision_recall_plot, read_dataset, reconstruction, roc_plot, sample_choices,
)
from model import FEATURES, load_saved_model, metrics, predict


def test_saved_metrics_and_matrix_sum():
    bundle = load_saved_model()
    summary = metrics(bundle, .50)
    assert summary["Accuracy"] > .9
    assert 0 < summary["ROC AUC"] <= 1
    assert len(bundle["test_y"]) == 12497
    assert int(np.asarray(summary["confusion_matrix"]).sum()) == len(bundle["test_y"])
    assert summary["confusion_matrix"] == [[6277, 796], [327, 5097]]


def test_real_csv_reproduces_saved_holdout_predictions():
    bundle = load_saved_model()
    raw = read_dataset()
    assert len(raw) == 62485
    assert len(cleaned_dataset(raw)) == 62485
    holdout = reconstruction(raw, bundle)
    assert len(holdout) == len(bundle["test_y"])
    positions = [0, 42, 989, len(holdout) - 1]
    selected = holdout.iloc[positions][FEATURES]
    inference = predict(bundle, selected)
    assert np.allclose(inference["Ransomware probability"], bundle["test_probability"][positions], atol=1e-10)


def test_all_sample_groups_have_actual_test_examples():
    groups = sample_choices(load_saved_model())
    assert len(groups) == 4
    assert all(0 < len(indices) <= 20 for indices in groups.values())
    assert all(len(indices) == len(set(indices)) for indices in groups.values())


def test_real_chart_figures_render():
    raw = read_dataset()
    bundle = load_saved_model()
    summary = metrics(bundle, .5)
    figs = [class_donut(raw), confusion_heatmap(summary["confusion_matrix"]),
            roc_plot(bundle, .5, summary["confusion_matrix"]),
            importance_plot(bundle, 12), precision_recall_plot(bundle)]
    for fig in figs:
        assert len(fig.data) >= 1
        assert fig.to_json()
