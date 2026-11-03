# 🛡️ SentinelTrace AI

### AI-Powered Network Intrusion Detection System

SentinelTrace AI is a machine learning-based cybersecurity
application that identifies suspicious network traffic using
a Random Forest classification model.

## Features

- Network traffic CSV upload
- Automated intrusion detection
- Normal and malicious traffic classification
- Intrusion probability scores
- Prediction confidence
- Threat severity classification
- Interactive traffic visualizations
- Downloadable security reports

## Technology Stack

- Python
- Pandas
- NumPy
- Scikit-learn
- Random Forest
- Streamlit
- Joblib
- SHAP

## Machine Learning

The project compares multiple classification algorithms:

- Logistic Regression
- Decision Tree
- Random Forest

Random Forest was selected as the final model.

## Model Performance

| Metric | Score |
|---|---:|
| Accuracy | 94.63% |
| Precision | 65.81% |
| Recall | 91.12% |
| F1 Score | 76.43% |
| ROC-AUC | 93.73% |

## Run Locally

Install dependencies:

pip install -r requirements.txt

Run application:

streamlit run app.py

## Author

Swaroop Sutar