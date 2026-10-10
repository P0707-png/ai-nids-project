import streamlit as st
import pandas as pd
import joblib
import time

st.set_page_config(page_title="AI-Driven NIDS Dashboard", layout="wide")
st.title("🛡️ AI-Driven Network Intrusion Detection Dashboard")

# Load model and feature columns
model = joblib.load("nids_model.pkl")
feature_columns = pd.read_csv("feature_columns.csv")["0"].tolist()

# Load test data (reuse your cleaned dataframe approach)
st.sidebar.header("Controls")
scan_count = st.sidebar.slider("Number of rows to scan", 5, 50, 10)
start_scan = st.sidebar.button("▶️ Start Live Scan")

st.write("This dashboard simulates live network traffic monitoring using a trained Random Forest model on the NSL-KDD dataset.")

if start_scan:
    df_test = pd.read_csv("KDDTest+.txt", header=None)
    columns = feature_columns + ["label", "difficulty_level"] if len(feature_columns) < df_test.shape[1] else feature_columns
    # NOTE: adjust this loading to match however you cleaned your training data

    progress = st.progress(0)
    status = st.empty()
    result = st.empty()

    for i in range(scan_count):
        row = df_test.iloc[[i]]
        row_features = row.reindex(columns=feature_columns, fill_value=0)

        pred = model.predict(row_features)[0]
        prob = model.predict_proba(row_features)[0]

        if pred == 1:
            result.error(f"🔴 Row {i}: ATTACK ({prob[1]*100:.2f}% confidence)")
        else:
            result.success(f"🟢 Row {i}: NORMAL ({prob[0]*100:.2f}% confidence)")

        progress.progress((i + 1) / scan_count)
        time.sleep(0.3)

    status.success("✅ Scanning completed!")
else:
    st.info("Click 'Start Live Scan' in the sidebar to begin monitoring simulated traffic.")
