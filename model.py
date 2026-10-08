"""Train-only preprocessing and inference shared by all UI modes."""
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from threadpoolctl import threadpool_limits

FEATURES = ['Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA', 'MajorLinkerVersion', 'MinorLinkerVersion', 'NumberOfSections', 'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize', 'BitcoinAddresses']
ENGINEERED = ['HasDebugInfo', 'HasExportTable', 'HasBitcoinAddress', 'LinkerVersion']
DATA_PATH = Path(__file__).parent / 'data_file.csv'

def validate(frame):
    if frame.empty:
        raise ValueError('The CSV contains no records.')
    if len(frame) > 100_000:
        raise ValueError('Please upload at most 100,000 records per batch.')
    missing = [c for c in FEATURES if c not in frame.columns]
    if missing:
        raise ValueError('Missing required columns: ' + ', '.join(missing))
    x = frame[FEATURES].apply(pd.to_numeric, errors='coerce')
    bad = x.columns[(~np.isfinite(x)).any()].tolist()
    if bad:
        raise ValueError('Missing, nonnumeric, or infinite values in: ' + ', '.join(bad))
    if (x < 0).any().any() or (x > 2**53 - 1).any().any():
        raise ValueError('Feature values must be between 0 and 9,007,199,254,740,991.')
    if (x % 1 != 0).any().any():
        raise ValueError('Raw PE feature values must be whole numbers.')
    return x.astype('float64')

def engineer(x):
    x = x.copy()
    x['HasDebugInfo'] = (x.DebugSize > 0).astype(int)
    x['HasExportTable'] = (x.ExportSize > 0).astype(int)
    x['HasBitcoinAddress'] = (x.BitcoinAddresses > 0).astype(int)
    x['LinkerVersion'] = x.MajorLinkerVersion + x.MinorLinkerVersion / 10.0
    return x

def load_saved_model():
    import json
    import joblib
    root = Path(__file__).parent / 'artifacts'
    classifier = joblib.load(root / 'logistic_regression_ransomware_model.joblib')
    scaler = joblib.load(root / 'feature_scaler.joblib')
    columns = joblib.load(root / 'feature_columns.joblib')
    if list(classifier.classes_) != [0, 1]:
        raise ValueError('Expected labels 0=ransomware and 1=benign.')
    if not hasattr(scaler, 'feature_names_in_'):
        raise ValueError('Export the scaler fitted on named columns in your notebook.')
    if classifier.n_features_in_ != len(columns):
        raise ValueError('Model and feature list do not match. Export all files together.')
    evaluation = root / 'evaluation.json'
    details = json.loads(evaluation.read_text()) if evaluation.exists() else None
    data = pd.read_csv(DATA_PATH)
    machines = {int(c.removeprefix('Machine_')) for c in columns if c.startswith('Machine_')}
    bundle = {'classifier': classifier, 'scaler': scaler, 'columns': columns,
              'data': data, 'machines': machines, 'evaluation': details}
    if details:
        bundle.update(test_y=pd.Series(details['test_y']),
                      test_probability=np.array(details['ransomware_probability']),
                      train_rows=details['train_rows'], test_rows=len(details['test_y']))
    return bundle

def transform(bundle, frame):
    x = engineer(validate(frame))
    x['Machine'] = x['Machine'].astype('int64')
    encoded = pd.get_dummies(x, columns=['Machine'], prefix='Machine')
    encoded = encoded.reindex(columns=bundle['columns'], fill_value=0)
    scaled_names = list(bundle['scaler'].feature_names_in_)
    encoded[scaled_names] = bundle['scaler'].transform(encoded[scaled_names])
    return encoded

def predict(bundle, frame, threshold=.5):
    x = transform(bundle, frame)
    classifier = bundle['classifier']
    p = classifier.predict_proba(x)[:, list(classifier.classes_).index(0)]
    result = frame.copy()
    result['Ransomware probability'] = p
    labels = classifier.predict(x) if threshold == .5 else np.where(p >= threshold, 0, 1)
    result['Prediction'] = np.where(labels == 0, 'Ransomware', 'Benign')
    result['Unseen machine code'] = ~pd.to_numeric(frame.Machine).isin(bundle['machines'])
    return result

def metrics(bundle, threshold=.5):
    actual = (bundle['test_y'] == 0).astype(int)
    pred = ((bundle['test_probability'] > threshold) if threshold == .5 else (bundle['test_probability'] >= threshold)).astype(int)
    return {'Accuracy': accuracy_score(actual, pred),
            'Ransomware precision': precision_score(actual, pred, zero_division=0),
            'Ransomware recall': recall_score(actual, pred, zero_division=0),
            'Ransomware F1': f1_score(actual, pred, zero_division=0),
            'ROC AUC': roc_auc_score(actual, bundle['test_probability']),
            'confusion_matrix': confusion_matrix(actual, pred, labels=[1, 0]).tolist()}
