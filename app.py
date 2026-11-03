import streamlit as st
import pandas as pd
import joblib

# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="SentinelTrace AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# CUSTOM CSS
# ==========================================

st.markdown("""
<style>
    .main {
        background-color: #0e1117;
    }

    .block-container {
        padding-top: 2rem;
    }

    .main-title {
        font-size: 38px;
        font-weight: 800;
        color: #58a6ff;
    }

    .subtitle {
        color: #a0aab8;
        font-size: 16px;
    }

    div[data-testid="stMetric"] {
        background-color: #171d29;
        border: 1px solid #303b4d;
        padding: 18px;
        border-radius: 12px;
    }

    .status-normal {
        color: #2ecc71;
        font-weight: bold;
    }

    .status-danger {
        color: #ff4b4b;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# ==========================================
# LOAD TRAINED MODEL
# ==========================================

@st.cache_resource
def load_model():
    return joblib.load("sentineltrace_rf_pipeline.pkl")


try:
    model = load_model()
except Exception as e:
    st.error(f"Unable to load model: {e}")
    st.stop()


# ==========================================
# HEADER
# ==========================================

st.markdown(
    '<div class="main-title">🛡️ SentinelTrace AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'AI-Powered Network Intrusion Detection System'
    '</div>',
    unsafe_allow_html=True
)

st.divider()


# ==========================================
# SIDEBAR
# ==========================================

st.sidebar.title("🛡️ SentinelTrace AI")

st.sidebar.markdown("""
### Dashboard
Monitor network traffic and identify suspicious activities.

### Model Information
- Algorithm: Random Forest
- Task: Binary Classification
- Classes: Normal / Intrusion
- Framework: Scikit-learn
""")

st.sidebar.divider()

st.sidebar.info(
    "Upload a network traffic CSV file to start analyzing."
)


# ==========================================
# REQUIRED FEATURES
# ==========================================

required_columns = [
    "Payload_Size",
    "Request_Type",
    "Protocol",
    "User_Agent",
    "Status"
]


# ==========================================
# FILE UPLOAD
# ==========================================

st.subheader("📂 Upload Network Traffic Data")

uploaded_file = st.file_uploader(
    "Upload your CSV dataset",
    type=["csv"],
    help="Upload a CSV containing the five required model features."
)


# ==========================================
# PROCESS DATA
# ==========================================

if uploaded_file is not None:

    try:
        df = pd.read_csv(uploaded_file)

        st.success("Dataset uploaded successfully!")

        # Dataset information
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Total Dataset Rows", len(df))

        with col2:
            st.metric("Total Dataset Columns", len(df.columns))

        st.subheader("📋 Dataset Preview")

        st.dataframe(
            df.head(10),
            use_container_width=True
        )

        # Check required columns
        missing_columns = [
            col for col in required_columns
            if col not in df.columns
        ]

        if missing_columns:

            st.error(
                f"Missing required columns: {missing_columns}"
            )

            st.stop()

        # Select model features in training order
        X = df[required_columns].copy()

        # Validate numerical feature
        X["Payload_Size"] = pd.to_numeric(
            X["Payload_Size"],
            errors="coerce"
        )

        if X["Payload_Size"].isna().any():

            st.error(
                "Payload_Size contains missing or invalid numeric values. "
                "Please correct the dataset before prediction."
            )

            st.stop()

        st.divider()

        st.subheader("🔍 Network Traffic Analysis")

        if st.button(
            "🚀 Analyze Network Traffic",
            use_container_width=True
        ):

            with st.spinner("Analyzing network traffic..."):

                # ==================================
                # MODEL PREDICTIONS
                # ==================================

                predictions = model.predict(X)

                probabilities = model.predict_proba(X)

                # Locate class 1 (Intrusion)
                classes = list(model.classes_)

                intrusion_index = classes.index(1)

                intrusion_probability = (
                    probabilities[:, intrusion_index] * 100
                )

                prediction_confidence = (
                    probabilities.max(axis=1) * 100
                )

                # ==================================
                # RESULTS DATAFRAME
                # ==================================

                results = df.copy()

                results["Prediction"] = predictions

                results["Threat_Status"] = (
                    results["Prediction"].map({
                        0: "Normal",
                        1: "Intrusion"
                    })
                )

                results["Intrusion_Probability"] = (
                    intrusion_probability.round(2)
                )

                results["Prediction_Confidence"] = (
                    prediction_confidence.round(2)
                )

                # ==================================
                # THREAT SEVERITY
                # ==================================

                def determine_severity(row):

                    if row["Prediction"] == 0:
                        return "Normal"

                    probability = row["Intrusion_Probability"]

                    if probability >= 90:
                        return "Critical"

                    elif probability >= 75:
                        return "High"

                    elif probability >= 50:
                        return "Medium"

                    else:
                        return "Low"

                results["Threat_Severity"] = results.apply(
                    determine_severity,
                    axis=1
                )

                # ==================================
                # SUMMARY METRICS
                # ==================================

                total_connections = len(results)

                total_intrusions = int(
                    (predictions == 1).sum()
                )

                total_normal = int(
                    (predictions == 0).sum()
                )

                intrusion_rate = (
                    total_intrusions / total_connections * 100
                    if total_connections > 0 else 0
                )

                # ==================================
                # DISPLAY METRICS
                # ==================================

                st.success("Analysis completed successfully!")

                st.subheader("📊 Security Overview")

                c1, c2, c3, c4 = st.columns(4)

                c1.metric(
                    "Total Connections",
                    f"{total_connections:,}"
                )

                c2.metric(
                    "Normal Traffic",
                    f"{total_normal:,}"
                )

                c3.metric(
                    "Intrusions Detected",
                    f"{total_intrusions:,}"
                )

                c4.metric(
                    "Intrusion Rate",
                    f"{intrusion_rate:.2f}%"
                )

                st.divider()

                # ==================================
                # THREAT ALERT
                # ==================================

                if total_intrusions > 0:

                    st.error(
                        f"⚠️ {total_intrusions} potential intrusions detected!"
                    )

                else:

                    st.success(
                        "✅ No potential intrusions detected."
                    )

                # ==================================
                # TRAFFIC CLASSIFICATION
                # ==================================

                st.subheader("📈 Traffic Classification")

                chart_data = pd.DataFrame({
                    "Traffic Type": [
                        "Normal",
                        "Intrusion"
                    ],
                    "Connections": [
                        total_normal,
                        total_intrusions
                    ]
                })

                st.bar_chart(
                    chart_data.set_index("Traffic Type")
                )

                # ==================================
                # THREAT SEVERITY CHART
                # ==================================

                st.subheader("🚨 Threat Severity Distribution")

                severity_order = [
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "Normal"
                ]

                severity_counts = (
                    results["Threat_Severity"]
                    .value_counts()
                    .reindex(severity_order, fill_value=0)
                )

                severity_df = pd.DataFrame({
                    "Severity": severity_counts.index,
                    "Count": severity_counts.values
                })

                st.bar_chart(
                    severity_df.set_index("Severity")
                )

                # ==================================
                # PREDICTION FILTER
                # ==================================

                st.divider()

                st.subheader("🔎 Filter Prediction Results")

                filter_option = st.selectbox(
                    "Select traffic category",
                    [
                        "All",
                        "Normal",
                        "Intrusion",
                        "Critical",
                        "High",
                        "Medium",
                        "Low"
                    ]
                )

                filtered_results = results.copy()

                if filter_option == "Normal":
                    filtered_results = results[
                        results["Threat_Status"] == "Normal"
                    ]

                elif filter_option == "Intrusion":
                    filtered_results = results[
                        results["Threat_Status"] == "Intrusion"
                    ]

                elif filter_option in severity_order:
                    filtered_results = results[
                        results["Threat_Severity"] == filter_option
                    ]

                # ==================================
                # RESULTS TABLE
                # ==================================

                st.subheader("📋 Prediction Results")

                st.caption(
                    f"Displaying {len(filtered_results):,} records"
                )

                st.dataframe(
                    filtered_results,
                    use_container_width=True,
                    height=450
                )

                # ==================================
                # DOWNLOAD RESULTS
                # ==================================

                st.divider()

                st.subheader("📥 Download Security Report")

                csv_data = results.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    label="⬇️ Download Complete Prediction Report",
                    data=csv_data,
                    file_name="sentineltrace_security_report.csv",
                    mime="text/csv",
                    use_container_width=True
                )

                # ==================================
                # DOWNLOAD INTRUSION RECORDS
                # ==================================

                intrusion_data = results[
                    results["Prediction"] == 1
                ]

                intrusion_csv = intrusion_data.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    label="⬇️ Download Intrusion Records Only",
                    data=intrusion_csv,
                    file_name="sentineltrace_intrusions.csv",
                    mime="text/csv",
                    use_container_width=True
                )

                # ==================================
                # FOOTER
                # ==================================

                st.divider()

                st.success(
                    "SentinelTrace AI analysis completed."
                )

    except Exception as e:

        st.error(f"An error occurred: {e}")


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.markdown(
    """
    <div style="text-align:center;color:#8993a4;">
        🛡️ SentinelTrace AI |
        AI-Powered Network Intrusion Detection |
        Built with Python, Scikit-learn & Streamlit
    </div>
    """,
    unsafe_allow_html=True
)