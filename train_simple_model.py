import os
import joblib
import json
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
TRAIN_FILE = r"C:\Users\user\PycharmProjects\NIDS - PROJECT\data\KDDTrain+.txt"
TEST_FILE = r"C:\Users\user\PycharmProjects\NIDS - PROJECT\data\KDDTest+.txt"
KDD_COLS = [
    "protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment",
    "urgent","hot","num_failed_logins","logged_in","num_compromised","root_shell",
    "su_attempted","num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label"
]

def load_data(path):

    try:
        df = pd.read_csv(path, names=KDD_COLS, header=None)
    except Exception as e:
        print("Error reading file:", e)
        raise
    return df

def preprocess(df):
    # minimal preprocessing: drop rows with missing, map label to numeric
    df = df.dropna()
    df['label'] = df['label'].astype(str)
    df['target'] = (df['label'] != 'normal.').astype(int)  # 1 = attack, 0 = normal
    # keep numeric columns only for example
    numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
    X = df[numeric_cols].copy()
    y = df['target'].copy()
    return X, y, numeric_cols

def train_and_save(X, y, feature_cols):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    pipe.fit(X_train, y_train)
    print("Train score:", pipe.score(X_train, y_train))
    print("Test score:", pipe.score(X_test, y_test))
    # Save model and feature list
    out_dir = os.path.join(os.path.dirname(__file__), "model_artifacts")
    os.makedirs(out_dir, exist_ok=True)
    joblib.dump(pipe, os.path.join(out_dir, "model.joblib"))
    with open(os.path.join(out_dir, "feature_columns.json"), "w") as f:
        json.dump(feature_cols, f)
    print("Saved model to", out_dir)

if __name__ == "__main__":
    print("Reading:", TRAIN_FILE)
    df = load_data(TRAIN_FILE)
    X, y, feat_cols = preprocess(df)
    train_and_save(X, y, feat_cols)
