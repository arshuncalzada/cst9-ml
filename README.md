# RansomGuard — Ransomware Detection Studio

A modern, **white-theme Streamlit dashboard** built specifically around the uploaded **`cst9-ml-main` project** and **`ransomware_logistic_regression_model(6).ipynb`**. It uses the original dataset, model, scaler, and test predictions rather than retraining or inventing scores.

## Run locally

Requires Python **3.11 or 3.12** (the model was exported with scikit-learn 1.6.1).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Streamlit typically opens `http://localhost:8501`. To deploy, upload the contents of this folder to GitHub, create a Streamlit Community Cloud app, select `app.py`, and ensure `data_file.csv` and `artifacts/` are present. No training step is required for the provided artifacts.

## Dashboard pages

| Page | What it does |
| --- | --- |
| Overview | Genuine dataset counts and class distribution, training/test split sizes, and model pipeline. |
| Model performance | Evaluation metrics, interactive threshold slider, confusion heatmap, ROC–AUC curve, precision–recall curve, and signed logistic feature coefficients. |
| Sample predictions | Select **actual held-out** records, compare the predicted label with dataset truth, and test changes to the 15 PE features. |
| File scanner | Read-only PE inspection of `.exe` and `.dll` files up to 20 MiB, with JSON download. |
| Manual analysis | Predict from all 15 PE fields, pre-populated with a real benign or ransomware record if the dataset is available. |

## Provenance and correctness

- Dataset: `data_file.csv`, 62,485 rows in the supplied CSV.
- Target: `Benign`: **0 = ransomware** and **1 = benign**.
- Trained method: **Logistic Regression**, not the Random Forest model in the design reference.
- Inputs: 15 raw PE fields; 4 engineered fields; one-hot encoding of `Machine`. Total: 24 model columns in the saved bundle.
- Saved artifacts: `artifacts/logistic_regression_ransomware_model.joblib`, `feature_scaler.joblib`, `feature_columns.joblib`, `evaluation.json`.
- The dashboard's metric curves use the 12,497 ground-truth labels and ransomware probabilities saved in `evaluation.json`.
- The sample page reconstructs the notebook's exact deduplicated, stratified 80/20 split (`random_state=42`), verifies labels and confirms sample predictions match the stored probabilities. If the dataset/artifacts disagree, it refuses to present mismatched samples.
- **Feature importance** is shown as the saved Logistic Regression coefficients (absolute magnitude for ordering, signed color for benign/ransomware direction), NOT Random Forest impurity-based importance.
- **Limitations:** notebook cell 13 fits `StandardScaler` on all data **before** cell 17 splits train/test, causing preprocessing leakage. Saved evaluation may be optimistic. The PE extractor's Bitcoin-address feature is heuristic, and performance on newly uploaded executable files has not been independently established. This is **not a certified malware detector**.

## File guide

- `app.py` — Streamlit dashboard, navigation and prediction pages.
- `dashboard_data.py` — dataset split verification and real-data Plotly charts.
- `dashboard_styles.py` — light color palette, CSS, cards and visual styling.
- `model.py` — original saved-model loading, feature processing and predictions (**unchanged**).
- `pe_extractor.py` — original read-only executable feature extraction (**unchanged**).
- `data_file.csv` — supplied training dataset (**unchanged**).
- `artifacts/` — supplied saved training/evaluation outputs (**unchanged**).
- `notebooks/ransomware_logistic_regression_model.ipynb` — an **unchanged copy** of your uploaded notebook for provenance and future retraining.

## Tests

```bash
pytest -q
```

You can also run the dashboard in Streamlit's AppTest environment (the tests include page navigation, confusion-matrix value checks, real sample alignment, and prediction handling). The layout is a design implementation, not a pixel-for-pixel reproduction of the referenced site.
