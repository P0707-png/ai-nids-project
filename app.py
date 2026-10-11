import time

import joblib
import pandas as pd
import streamlit as st

st.set_page_config(page_title="AI-Driven NIDS Dashboard", layout="wide")

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level",
]


@st.cache_resource
def load_model():
    model = joblib.load("nids_model.pkl")
    feature_columns = pd.read_csv("feature_columns.csv")["0"].tolist()
    return model, feature_columns


@st.cache_data
def load_test_data(feature_columns):
    raw = pd.read_csv("KDDTest+.txt", header=None, names=COLUMNS)
    actual = raw["label"].apply(lambda x: "normal" if x == "normal" else "attack")

    # Same cleaning and encoding as the training pipeline
    features = raw.drop(columns=["label", "difficulty_level"])
    features = pd.get_dummies(features, columns=["protocol_type", "service", "flag"])
    features = features.reindex(columns=feature_columns, fill_value=0).astype(float)
    return raw, features, actual


model, feature_columns = load_model()
raw, features, actual = load_test_data(feature_columns)

st.title("🛡️ AI-Driven Network Intrusion Detection Dashboard")
st.write(
    "Replays random connections from the NSL-KDD test file through a trained "
    "Random Forest and flags each one as normal or attack."
)

st.sidebar.header("Controls")
n_rows = st.sidebar.slider("Connections to scan", 10, 100, 30)
delay = st.sidebar.slider("Delay per connection (seconds)", 0.0, 1.0, 0.3, 0.1)
start = st.sidebar.button("▶️ Start Live Scan")

if not start:
    st.info("Click 'Start Live Scan' in the sidebar to begin monitoring simulated traffic.")
    st.stop()

sample_idx = features.sample(n=n_rows).index

c1, c2, c3 = st.columns(3)
normal_box = c1.empty()
attack_box = c2.empty()
match_box = c3.empty()
verdict = st.empty()
progress = st.progress(0)
table = st.empty()

rows = []
n_normal = n_attack = n_match = 0

for step, idx in enumerate(sample_idx, start=1):
    x = features.loc[[idx]]
    pred = int(model.predict(x)[0])
    conf = float(model.predict_proba(x)[0].max())
    verdict_label = "attack" if pred == 1 else "normal"
    true_label = actual.loc[idx]
    matched = verdict_label == true_label

    if pred == 1:
        n_attack += 1
        verdict.error(f"🔴 Connection {step}: ATTACK ({conf * 100:.1f}% confidence)")
    else:
        n_normal += 1
        verdict.success(f"🟢 Connection {step}: NORMAL ({conf * 100:.1f}% confidence)")
    n_match += int(matched)

    rows.append({
        "#": step,
        "protocol": raw.loc[idx, "protocol_type"],
        "service": raw.loc[idx, "service"],
        "flag": raw.loc[idx, "flag"],
        "src_bytes": raw.loc[idx, "src_bytes"],
        "dst_bytes": raw.loc[idx, "dst_bytes"],
        "verdict": verdict_label,
        "confidence": f"{conf * 100:.1f}%",
        "actual": true_label,
        "match": "✅" if matched else "❌",
    })

    normal_box.metric("Flagged normal", n_normal)
    attack_box.metric("Flagged attack", n_attack)
    match_box.metric("Agreement with true label", f"{n_match / step * 100:.0f}%")
    table.dataframe(pd.DataFrame(rows[::-1]), hide_index=True)
    progress.progress(step / n_rows)
    time.sleep(delay)

st.success(
    f"✅ Scan complete: {n_attack} attacks flagged, {n_normal} normal, "
    f"{n_match / n_rows * 100:.0f}% agreement with the dataset's true labels."
)
