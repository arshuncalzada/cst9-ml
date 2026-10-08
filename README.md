# Ransomware Detection Using Logistic Regression Classification

Streamlit UI that **loads an already-trained Logistic Regression model** for binary classification of static Windows PE (Portable Executable) header features, where `0 = ransomware` and `1 = benign`.

## New: upload `.exe` or `.dll` files

The **Upload .exe / .dll** tab reads a PE file into memory and extracts 15 raw features before passing them to the saved model, using exactly the same `model.py` preprocessing and classifier as the other UI modes. **Uploaded code is never executed or saved by the application.**

The static extractor uses Python's standard library. It handles Windows **PE32 and PE32+** optional headers and reads:

- COFF `Machine`, `NumberOfSections`
- Optional header `MajorImageVersion`, `MajorOSVersion`, `MajorLinkerVersion`, `MinorLinkerVersion`, `SizeOfStackReserve`, `DllCharacteristics`
- Data directories' `DebugSize`, `DebugRVA`, `ExportRVA`, `ExportSize`, `IatVRA` (spelling retained from original dataset), `ResourceSize`
- `BitcoinAddresses`: **heuristic binary 0/1** from checksummed visible Bitcoin wallet strings (legacy/SegWit). This has **not** been verified as equivalent to how the Kaggle dataset generated this field. Encoded, packed, or obfuscated addresses are not found.

The upload tab displays the file's SHA-256, PE type, extracted feature table, a classifier prediction, and a downloadable feature CSV compatible with the **Batch CSV** tab.

**Important limits:** Uploaded-file classification has **not** been independently benchmarked against the dataset; the notebook's reported held-out accuracy should **not** be interpreted as a measured `.exe/.dll` detection rate. Incorrect predictions, especially false benign results, are possible. This is a research demonstration, **not** an antivirus or a safe-file certification tool. Avoid uploading actual malicious files to a public hosted instance; prefer an isolated local testing environment.

## Deploy on Streamlit Community Cloud

1. Upload this project's contents **including all files and folders** to the root of your GitHub repository (`app.py`, `model.py`, `pe_extractor.py`, `data_file.csv`, `requirements.txt`, `artifacts/`, `.streamlit/`). Do not upload `cst9-ml-main` as an extra containing directory.
2. Check `artifacts/` contains:
   - `logistic_regression_ransomware_model.joblib`
   - `feature_scaler.joblib`
   - `feature_columns.joblib`
   - `evaluation.json`
3. Open https://share.streamlit.io, create an app from your repository, select main file **`app.py`**, and select **Python 3.12**.
4. Deploy. To update an existing app, commit the changed files to the same GitHub branch and let Streamlit Cloud redeploy.
5. Test the **Upload .exe / .dll** tab with a trusted Windows executable or DLL under 20 MiB. It must be a PE32/PE32+ file (a renamed text file will be rejected).

Requirements pin **scikit-learn 1.6.1**, matching the supplied notebook artifacts' recorded training version. Keep model, scaler, and columns together and never load `.joblib` files from untrusted users.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests use synthetic PE header **fixtures**, not malware, to verify both PE32 and PE32+ extraction, invalid-file rejection, and compatibility with model feature names. Tests do not establish real-world detection accuracy.

## Existing tabs

- **Single prediction**: enter 15 raw features manually or load a labeled dataset example.
- **Batch CSV**: predict many already-extracted feature rows and download CSV predictions.
- **Model performance**: show stored notebook evaluation, confusion matrix, and model coefficients. Results are from the saved notebook evaluation, not validation of the PE upload extractor.
- **How it works**: describe the preprocessing and important caveats.

The source notebook fitted the scaler before splitting its data, which can inflate the reported accuracy. To obtain rigorous held-out results, fix preprocessing in the notebook, rerun the evaluation on held-out real data, and re-export all artifacts together.
