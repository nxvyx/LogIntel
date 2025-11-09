import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
import tempfile
import os
from ingest_and_detect import run_detection, generate_sample_logs
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import io

# --- Setup ---
st.set_page_config(page_title="LogIntel", layout="wide")
ROOT = Path(".")
KB_DIR = ROOT / "knowledge_articles"
INCIDENTS_CSV = ROOT / "detected_incidents.csv"
SAMPLE_LOGS_CSV = ROOT / "sample_logs.csv"

# ---------- FIXED NAVIGATION & PAGE STATE ----------
# ensure a session-state key exists
if "page" not in st.session_state:
    st.session_state["page"] = "Home"

# Define available navigation pages
nav_options = ["Home", "Run Analysis", "About"]

# Determine which option is currently selected (keeps sidebar + button in sync)
try:
    current_index = nav_options.index(st.session_state.get("page", "Home"))
except ValueError:
    current_index = 0

# Sidebar Navigation
st.sidebar.title(" Navigation")
selected = st.sidebar.radio("Go to", nav_options, index=current_index)
st.session_state["page"] = selected
st.sidebar.markdown("---")
st.sidebar.caption("LogIntel — Smart Threat Detection Dashboard")

# Helper function to jump to another page and refresh
def go_to(page_name):
    st.session_state["page"] = page_name
    st.experimental_rerun()

# ---------------------------------------------------
# HOME PAGE
# ---------------------------------------------------
def show_home():
    st.title(" LogIntel — Smart Threat Detection Dashboard")
    st.markdown("""
    ### Welcome to LogIntel
    A **Security Operations Dashboard** esigned to analyze system and network logs,  
        detect potential security incidents, and automatically generate knowledge base reports.
        
    *Built for learning, research, and portfolio demonstration — this tool showcases how ML and rule-based analysis can be combined to enhance visibility and response in modern security environments.*

    ---
    
    **Features:**
    - Smart log ingestion & anomaly detection (Rule + ML based)
    - Real-time incident correlation and severity scoring
    - Auto-generated knowledge base for each detected event
    - Interactive dashboards and filtering

    ---
    """)
    
    st.markdown("### Get Started")
    st.write(
        "Click below to launch the analysis dashboard where you can either use sample logs "
        "or upload your own security logs for detection."
    )
    # on Home page: start button that navigates reliably
    if st.button("Start Detection", use_container_width=True):
        go_to("Run Analysis")

# ---------------------------------------------------
# ANALYSIS PAGE
# ---------------------------------------------------
def show_analysis():
    st.title("LogIntel — Smart Threat Detection Dashboard")
    st.markdown(
        "Run detection on sample logs or upload your own. "
        "This prototype demonstrates log ingestion, rule-based + ML detection, risk scoring, and KB automation."
    )

    # --- Sidebar / Controls ---
    st.sidebar.subheader("Analysis Controls")
    mode = st.sidebar.radio("Mode", ["Use Sample Logs", "Upload Logs"])
    contamination = st.sidebar.slider("ML contamination (anomaly sensitivity)", 0.01, 0.2, 0.05, 0.01)
    recreate_sample = st.sidebar.checkbox("Regenerate sample logs (fresh)", value=False)
    st.sidebar.markdown("---")
    st.sidebar.caption("Tip: Upload CSV or JSON logs with timestamp,user,source_ip,event")

    # --- Handle sample regeneration ---
    if recreate_sample:
        st.info("Regenerating sample logs...")
        generate_sample_logs(n=1500, out_csv=str(SAMPLE_LOGS_CSV))
        st.success("Sample logs regenerated.")

    # --- File uploader ---
    uploaded_file = None
    if mode == "Upload Logs":
        uploaded_file = st.file_uploader("Upload your logs (.csv or .json)", type=["csv", "json"])
        st.markdown("---")

    # --- Run detection button ---
    run_btn = st.button("Run Detection")

    # --- Helper: process uploaded logs ---
    def handle_uploaded_and_run(uploaded):
        tmpdir = tempfile.mkdtemp()
        tmp_path = Path(tmpdir) / "uploaded_logs.csv"
        try:
            if uploaded.name.endswith(".csv"):
                df = pd.read_csv(uploaded)
            else:
                df = pd.read_json(uploaded)
            expected_cols = {"timestamp", "user", "source_ip", "event"}
            if not expected_cols.issubset(df.columns):
                st.warning(f"Uploaded file missing expected columns. Found: {list(df.columns)}")
            df.to_csv(tmp_path, index=False)
        except Exception as e:
            st.error(f"Failed to parse uploaded file: {e}")
            return None
        out_inc = Path(tmpdir) / "detected_incidents.csv"
        kb_out_dir = Path(tmpdir) / "knowledge_articles"
        kb_out_dir.mkdir(parents=True, exist_ok=True)
        try:
            inc_df = run_detection(
                log_csv=str(tmp_path), out_incidents=str(out_inc), kb_dir=str(kb_out_dir)
            )
        except Exception as e:
            st.error(f"Detection pipeline error: {e}")
            return None
        return {"inc_df": inc_df, "kb_dir": kb_out_dir, "tmpdir": tmpdir}

    # --- Helper: run on sample logs ---
    def run_on_sample():
        if not SAMPLE_LOGS_CSV.exists():
            generate_sample_logs(n=1500, out_csv=str(SAMPLE_LOGS_CSV))
        inc_df = run_detection(
            log_csv=str(SAMPLE_LOGS_CSV),
            out_incidents=str(INCIDENTS_CSV),
            kb_dir=str(KB_DIR),
        )
        return {"inc_df": inc_df, "kb_dir": KB_DIR, "tmpdir": None}

    # --- Run detection ---
    context = None
    if run_btn:
        if mode == "Use Sample Logs":
            with st.spinner("Running detection on sample logs..."):
                context = run_on_sample()
            if context:
                st.success("Detection complete on sample logs.")
        else:
            if uploaded_file is None:
                st.warning("Please upload a log file first (CSV or JSON).")
            else:
                with st.spinner("Parsing uploaded file and running detection..."):
                    context = handle_uploaded_and_run(uploaded_file)
                if context:
                    st.success("Detection complete on uploaded logs.")

    if context is None and INCIDENTS_CSV.exists():
        try:
            inc_df = pd.read_csv(INCIDENTS_CSV, parse_dates=["timestamp"])
            context = {"inc_df": inc_df, "kb_dir": KB_DIR, "tmpdir": None}
        except Exception:
            context = None

    # --- Display results ---
    if context and context["inc_df"] is not None:
        inc_df = context["inc_df"]
        if "timestamp" in inc_df.columns:
            inc_df["timestamp"] = pd.to_datetime(inc_df["timestamp"])

        st.subheader("Incidents Summary")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Incidents", int(len(inc_df)))
        col2.metric("High Severity (≥8)", int((inc_df["severity_score"] >= 8).sum()))
        col3.metric("External Incidents", int(inc_df["is_external"].sum()))
        col4.metric("Users Involved", inc_df["user"].nunique())

        st.markdown("---")
        st.markdown("### Filter Incidents")
        type_list = sorted(inc_df["type"].unique().tolist())
        user_list = sorted(inc_df["user"].astype(str).unique().tolist())
        sev_min, sev_max = st.slider("Severity Range", 0, 10, (0, 10))
        selected_types = st.multiselect("Incident Types", type_list, default=type_list)
        selected_users = st.multiselect("Users", user_list, default=user_list[:10])
        filtered = inc_df[
            (inc_df["severity_score"] >= sev_min)
            & (inc_df["severity_score"] <= sev_max)
            & (inc_df["type"].isin(selected_types))
            & (inc_df["user"].astype(str).isin(selected_users))
        ]
        st.dataframe(
            filtered[
                ["incident_id", "timestamp", "type", "user", "source_ip", "severity_score"]
            ].sort_values("severity_score", ascending=False),
            height=300,
        )

        # Trend chart
        st.subheader("Incident Trend")
        if "timestamp" in inc_df.columns:
            trend = inc_df.set_index("timestamp").resample("1H").size().reset_index(name="count")
            fig = px.line(trend, x="timestamp", y="count", title="Incidents per Hour")
            st.plotly_chart(fig, use_container_width=True)

        # Heatmap
        st.subheader("Risk Heatmap (Avg Severity by Type & User)")
        pivot = filtered.pivot_table(
            index="type", columns="user", values="severity_score", aggfunc="mean"
        ).fillna(0)
        if not pivot.empty:
            fig2 = px.imshow(
                pivot,
                labels=dict(x="User", y="Incident Type", color="Avg Severity"),
                x=pivot.columns,
                y=pivot.index,
                title="Avg Severity Heatmap",
            )
            st.plotly_chart(fig2, use_container_width=True)

        # Knowledge Base
        st.subheader("Knowledge Base Articles")
        kb_dir = context["kb_dir"]
        kb_files = []
        if kb_dir and Path(kb_dir).exists():
            kb_files = sorted(Path(kb_dir).glob("*.md"))
        if kb_files:
            selected = st.selectbox("Select KB article", [p.name for p in kb_files])
            if selected:
                content = (Path(kb_dir) / selected).read_text()
                st.markdown(f"### {selected}")
                st.code(content, language="markdown")
        else:
            st.info("No KB articles found. Run detection to generate KBs.")

    else:
        st.info("No detection run found. Choose a mode and press **Run Detection** to start.")


    # --- PDF Export Function ---
    def generate_pdf_report(df):
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()

        title = Paragraph("<b>LogIntel — Security Incident Report</b>", styles["Title"])
        timestamp = Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"])

        elements.extend([title, Spacer(1, 12), timestamp, Spacer(1, 24)])

        # Summary
        summary_text = f"""
        <b>Total Incidents:</b> {len(df)}<br/>
        <b>High Severity (>=8):</b> {(df['severity_score'] >= 8).sum()}<br/>
        <b>Unique Users:</b> {df['user'].nunique()}<br/>
        <b>External Incidents:</b> {int(df['is_external'].sum())}
        """
        elements.append(Paragraph(summary_text, styles["Normal"]))
        elements.append(Spacer(1, 24))

        # Incident table (top 10 for readability)
        subset = df[['incident_id', 'timestamp', 'type', 'user', 'source_ip', 'severity_score']].head(10)
        table_data = [subset.columns.tolist()] + subset.astype(str).values.tolist()
        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 24))

        elements.append(Paragraph("This report is automatically generated by LogIntel for analysis and review purposes.", styles["Italic"]))
        doc.build(elements)
        buffer.seek(0)
        return buffer

    # --- Add this under your incident results section ---
    if not filtered.empty:
        pdf_buffer = generate_pdf_report(filtered)
        st.download_button(
            label="Export Report as PDF",
            data=pdf_buffer,
            file_name="LogIntel_Incident_Report.pdf",
            mime="application/pdf"
        )

# ---------------------------------------------------
# ABOUT PAGE
# ---------------------------------------------------
def show_about():
    st.title("About LogIntel")
    st.markdown("""
    **LogIntel** is a prototype cybersecurity assistant built to demonstrate automated threat detection, incident classification, and knowledge-driven response.
    """)
    st.markdown("---")
    st.subheader("Key Capabilities")

    st.markdown(
        """
        - Real-time detection of suspicious log entries  
        - Hybrid rule-based + ML anomaly detection  
        - Automatic generation of incident summaries and reports  
        - Interactive dashboards for visualization and trend analysis  
        - Modular architecture for SIEM/SOC integration  
        """
    )
    st.markdown("---")
    st.subheader("Technology Stack")
    st.markdown(
        """
        - **Python**, **Streamlit**, **Pandas**, **Scikit-learn**  
        - Visualization: **Plotly**, **Matplotlib**  
        - Markdown-based **Knowledge Base System**  
        """
    )
    
# ---------------------------------------------------
# MAIN PAGE ROUTER
current_page = st.session_state.get("page", "Home")

if current_page == "Home":
    show_home()
elif current_page == "Run Analysis":
    show_analysis()
elif current_page == "About":
    show_about()
