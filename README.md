# LogIntel — Smart Threat Detection Dashboard

**LogIntel** is an AI-driven cybersecurity incident analysis and monitoring dashboard.  
It demonstrates how security logs can be ingested, analyzed, and visualized to detect anomalous or malicious activities in a simulated SOC environment.

---

## Features

- **Hybrid Detection Engine**  
  Combines **rule-based checks** and **machine learning (Isolation Forest)** for anomaly detection.

- **Interactive Dashboard**  
  Built with Streamlit and Plotly for:
  - Incident trend visualization  
  - Heatmaps of severity vs. user/type  
  - Filtering by severity, user, and type

- **Knowledge Base Generation**  
  Automatically generates markdown-based reports for detected incidents.

- **Upload & Sample Logs Support**  
  - Upload your own CSV/JSON logs  
  - Use built-in sample logs for testing

- **PDF Export**  
  Export a full incident report with summary and top incidents in PDF format.

---

## 🛠️ Technology Stack

- **Language & Libraries:** Python, Pandas, Scikit-learn, Streamlit, Plotly  
- **Visualization:** Trend lines, heatmaps, interactive tables  
- **Reporting:** Markdown KB articles, PDF export with `reportlab`  
- **Machine Learning:** Isolation Forest for anomaly detection  

---

## 📊 Screenshots / Demo



https://github.com/user-attachments/assets/57e144ce-6302-41d0-8ca2-556b0e25db50


<img width="1403" height="891" alt="image" src="https://github.com/user-attachments/assets/13e09d30-b0bc-4039-aedb-64d8e2bde0ea" />

<img width="1295" height="588" alt="image" src="https://github.com/user-attachments/assets/5a5295c5-5f68-4803-9eaf-df97f9bc2d0a" />

<img width="1340" height="783" alt="image" src="https://github.com/user-attachments/assets/a3dd43e8-58fe-4582-a701-6e2ac6d4a956" />

<img width="1311" height="987" alt="image" src="https://github.com/user-attachments/assets/48c24a31-2612-42f3-9045-d06513be4c15" />

## ⚡ Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/LogIntel.git
cd LogIntel
````

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the Streamlit dashboard:

```bash
streamlit run streamlit_app.py
```

---

## 📝 Usage

1. Open the Home page.
2. Choose **Use Sample Logs** or **Upload Logs**.
3. Press ** Start Detection**.
4. View detected incidents, trends, heatmaps, and knowledge base articles.
5. Export incidents as **CSV** or **PDF**.

---

## 💡 Learning Outcomes / Skills Demonstrated

* Security analytics & incident detection workflows
* Log analysis and preprocessing
* ML-based anomaly detection in real-world-like logs
* Interactive dashboards and visualization
* Automation: Knowledge base & reporting

---

## 🏷️ Future Enhancements

* MITRE ATT&CK mapping for detected incidents
* Real-time log streaming simulation
* SOC playbook automation for response actions
* Embedding charts into PDF reports

---

## 📂 Repository Structure

```
LogIntel/
├── streamlit_app.py        # Main dashboard
├── ingest_and_detect.py    # Detection & ML logic
├── sample_logs.csv         # Sample log file
├── knowledge_articles/     # Generated KB markdown files
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```
