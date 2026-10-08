# Validation summary

- Byte-level PE32 (32-bit) and PE32+ (64-bit) synthetic header fixtures parsed successfully.
- DLL flag, data-directory offsets, major/minor version headers, 32/64-bit stack reserve, feature names, and legacy Bitcoin address detection tested.
- Invalid or oversized files rejected without being executed.
- The extracted 15 fields match the existing `model.FEATURES` schema.
- Both synthetic PE fixture types were passed through `load_saved_model()` / `predict()` with the **bundled real saved model**; predictions were successfully returned.
- `evaluation.json` is from a `kagglehub` run; the saved test-label/probability results produce approximately 91.01% accuracy. This does **not** validate detection performance on newly uploaded executable files.
- `app.py`, `model.py`, and `pe_extractor.py` compiled successfully.
- The Streamlit GUI itself was **not runtime-tested locally** because the Streamlit package is not installed in this offline testing environment. GitHub/Streamlit Cloud deployment was not performed here.
- `requirements.txt` pins scikit-learn 1.6.1 to match the exported model's recorded training version; local inference tests used the runtime's installed 1.8.0, so the cloud build should be checked with pinned requirements.
- BitcoinAddresses from file bytes is heuristic and may not match the Kaggle dataset's extraction method. Generalization to real executables has not been assessed.
