# RansomGuard v2 validation and limitations

## Completed in this editing session

- Reviewed `cst9-ml-main` and all 29 notebook cells in `ransomware_logistic_regression_model(6).ipynb`.
- Confirmed the supplied CSV has **62,485 rows**, zero missing values, and **no duplicate MD5s**.
- Reconstructed the notebook's 80/20 stratified held-out records in the saved evaluation order.
- Independently confirmed held-out model predictions match the persisted ransomware probabilities (floating-point tolerance).
- Plotted real confusion counts, ROC and precision–recall curves, and actual saved Logistic Regression coefficients.
- Retained the original model, scaler, PE extractor, file data, and evaluation artifacts unchanged.
- Added code/data/chart tests. **8 pytest tests passed, with 4 pytest subtests.**

## Limitations of this validation

- In the validation container scikit-learn 1.8.0 generated warnings when reading a saved model exported using 1.6.1. The project pins 1.6.1, matching the notebook.
- Streamlit was **not installed** in the container, and installing it was blocked by network resolution failures. Therefore, Streamlit `AppTest` and browser-based visual checks could **not** be completed in this editing session. Run `pip install -r requirements.txt && streamlit run app.py` on Python 3.11/3.12 to verify the interactive pages.
- The specified reference Streamlit URL could not be fetched in this session. The new design follows the requested page structure and features, not a pixel-perfect rendering of that live URL.
- No deployment was performed; the downloadable ZIP contains the implementation.

## Scientific limitations

- The notebook fits StandardScaler on the complete dataset before splitting. This means there is preprocessing leakage and the test metrics can be optimistic.
- Ransomware classification of user-uploaded executable files has not been tested on an independent real-world malware benchmark.
- Static file scanning and Bitcoin-address extraction are heuristic. Do not use this project to certify a file as safe.
