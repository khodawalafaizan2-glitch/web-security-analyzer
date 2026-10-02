# Web Security Analyzer

A Python and Streamlit-based defensive security configuration analyzer for websites that you own or are authorized to assess.

## Features

* HTTP / HTTPS analysis
* Security header analysis
* Cookie security flag analysis
* CORS configuration review
* Information exposure checks
* SQLite scan history
* Security score
* Findings summary
* Professional PDF security report
* Streamlit dashboard

## Project Structure

```text
web-security-analyzer/
├── app.py
├── analyzer.py
├── database.py
├── report.py
├── requirements.txt
├── .gitignore
├── .streamlit/
│   └── config.toml
└── scans.db
```

## Technologies

* Python
* Streamlit
* Requests
* SQLite
* Pandas
* ReportLab

## Installation

Clone the repository:

```bash
git clone https://github.com/khodawalafaizan2-glitch/web-security-analyzer.git
cd web-security-analyzer
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the Application

```bash
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal.

## Usage

Enter a website URL that you own or are explicitly authorized to assess.

The analyzer performs normal HTTP/HTTPS requests and reviews configuration such as:

* Security headers
* Cookies
* CORS
* Information exposure
* HTTPS status


## Security Notice

This project is intended for authorized defensive security configuration assessment only.

Do not use it to test websites without permission.

## Author

FAIZAN
