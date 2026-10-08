# Saved-model UI validation

- App compilation checked.
- Missing-artifact screen tested with Streamlit AppTest.
- In an isolated fixture, the UI's transformed matrix matched notebook preprocessing exactly, and UI labels matched the saved classifier's predictions.
- The notebook export cell was executed successfully against the fixture.
- No fixture model is included in this package. The original user's fitted artifacts were not attached; their particular model cannot be verified until exported.
- No deployment has been performed. Model scores are shown only when evaluation data is supplied.
