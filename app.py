import streamlit as st

from analyzer import analyze_website
from database import (
    create_database,
    save_scan,
    get_scan_history
)
from report import create_security_report

# =====================================
# CUSTOM CSS
# =====================================

st.markdown("""
<style>

    /* Main background */
    .stApp {
        background-color: #f5f7fb;
    }

    /* Main title */
    h1 {
        color: #1f2937;
        font-weight: 700;
    }

    /* Section headings */
    h2, h3 {
        color: #374151;
    }

    /* Buttons */
    .stButton > button {
        width: 100%;
        border-radius: 8px;
        border: none;
        padding: 10px 20px;
        font-weight: 600;
        background-color: #2563eb;
        color: white;
        transition: 0.2s;
    }

    .stButton > button:hover {
        background-color: #1d4ed8;
        color: white;
    }

    /* Input boxes */
    .stTextInput input {
        border-radius: 8px;
        border: 1px solid #d1d5db;
        padding: 10px;
    }

    /* Metrics */
    [data-testid="stMetric"] {
        background-color: white;
        padding: 15px;
        border-radius: 12px;
        border: 1px solid #e5e7eb;
        box-shadow: 0px 2px 8px rgba(0,0,0,0.05);
    }

    /* Tables */
    [data-testid="stDataFrame"] {
        border-radius: 10px;
        overflow: hidden;
    }

    /* Expanders */
    .streamlit-expanderHeader {
        font-weight: 600;
        border-radius: 8px;
    }

    /* Dividers */
    hr {
        border-color: #e5e7eb;
    }

    /* Success messages */
    [data-testid="stAlert"] {
        border-radius: 8px;
    }

</style>
""", unsafe_allow_html=True)

# =====================================
# CREATE DATABASE
# =====================================

create_database()


# =====================================
# PAGE CONFIGURATION
# =====================================

st.set_page_config(
    page_title="Web Security Analyzer",
    page_icon="🛡️"
)


# =====================================
# TITLE
# =====================================

st.title("🛡️ Web Security Analyzer")

st.write(
    "Analyze basic security configuration of a website "
    "that you own or are authorized to test."
)


# =====================================
# WEBSITE SCANNER
# =====================================

url = st.text_input(
    "Enter website URL",
    placeholder="https://example.com"
)


if st.button("Start Scan"):

    if not url:

        st.warning(
            "Please enter a website URL."
        )

    else:

        with st.spinner(
            "Analyzing website..."
        ):

            result = analyze_website(url)


        if "error" in result:

            st.error(
                "Could not analyze the website."
            )

            st.code(
                result["error"]
            )

        else:

            # =====================================
            # SAVE SCAN
            # =====================================

            save_scan(result)

            st.success(
                "Scan completed and saved."
            )


            # =====================================
            # BASIC INFORMATION
            # =====================================

            st.subheader(
                "Basic Information"
            )

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric(
                    "HTTP Status",
                    result["status_code"]
                )

            with col2:

                st.metric(
                    "HTTPS",
                    "Enabled"
                    if result["https"]
                    else "Not detected"
                )

            with col3:

                st.metric(
                    "Server",
                    result["server"]
                    or "Not disclosed"
                )


            # =====================================
            # SECURITY HEADERS
            # =====================================

            st.subheader(
                "Security Headers"
            )

            for header, info in result[
                "security_headers"
            ].items():

                if info["status"] == "PASS":

                    st.success(
                        f"✅ {header} — PASS"
                    )

                else:

                    st.warning(
                        f"⚠️ {header} — WARN"
                    )

                st.write(
                    f"**Description:** "
                    f"{info['description']}"
                )

                st.write(
                    f"**Value:** {info['value']}"
                )

                st.divider()


            # =====================================
            # COOKIE SECURITY
            # =====================================

            st.subheader(
                "🍪 Cookie Security"
            )

            if not result["cookies"]:

                st.info(
                    "No cookies were returned "
                    "by the initial request."
                )

            else:

                for cookie in result["cookies"]:

                    st.markdown(
                        f"### 🍪 {cookie['name']}"
                    )

                    col1, col2, col3 = st.columns(3)

                    with col1:

                        if cookie["secure"]:

                            st.success(
                                "✅ Secure"
                            )

                        else:

                            st.warning(
                                "⚠️ Secure missing"
                            )

                    with col2:

                        if cookie["httponly"]:

                            st.success(
                                "✅ HttpOnly"
                            )

                        else:

                            st.warning(
                                "⚠️ HttpOnly missing"
                            )

                    with col3:

                        if cookie["samesite"] != "Not detected":

                            st.success(
                                f"✅ SameSite: "
                                f"{cookie['samesite']}"
                            )

                        else:

                            st.warning(
                                "⚠️ SameSite missing"
                            )

                    st.divider()


            # =====================================
            # CORS
            # =====================================

            st.subheader(
                "🌐 CORS Configuration"
            )

            cors = result["cors"]

            if cors["status"] == "REVIEW":

                st.warning(
                    "⚠️ CORS configuration "
                    "requires review."
                )

            elif cors["status"] == "PASS":

                st.success(
                    "✅ CORS specific "
                    "origin detected."
                )

            else:

                st.info(
                    "ℹ️ CORS header not detected."
                )

            st.write(
                f"**Access-Control-Allow-Origin:** "
                f"{cors['origin']}"
            )

            st.write(
                f"**Access-Control-Allow-Credentials:** "
                f"{cors['credentials']}"
            )

            st.write(
                f"**Access-Control-Allow-Methods:** "
                f"{cors['methods']}"
            )

            st.write(
                f"**Access-Control-Allow-Headers:** "
                f"{cors['headers']}"
            )

            st.caption(
                cors["message"]
            )


            # =====================================
            # INFORMATION EXPOSURE
            # =====================================

            st.subheader(
                "🔎 Information Exposure"
            )

            for finding in result[
                "information_exposure"
            ]:

                if finding["status"] == "REVIEW":

                    st.warning(
                        f"⚠️ {finding['name']} "
                        f"— REVIEW"
                    )

                else:

                    st.success(
                        f"✅ {finding['name']} "
                        f"— PASS"
                    )

                st.write(
                    f"**Value:** "
                    f"{finding['value']}"
                )

                st.write(
                    f"**Description:** "
                    f"{finding['description']}"
                )

                st.divider()


            # =====================================
            # ALL RESPONSE HEADERS
            # =====================================

            with st.expander(
                "View All Response Headers"
            ):

                for name, value in result[
                    "headers"
                ].items():

                    st.write(
                        f"**{name}:** {value}"
                    )


# =====================================
# SCAN HISTORY
# =====================================

st.divider()

st.subheader(
    "📋 Scan History"
)

history = get_scan_history()


if not history:

    st.info(
        "No previous scans available."
    )

else:

    for scan in history:

        scan_id = scan[0]
        scan_url = scan[1]
        scan_time = scan[2]
        status_code = scan[3]
        https = scan[4]
        server = scan[5]

        with st.expander(
            f"Scan #{scan_id} — "
            f"{scan_url} — "
            f"{scan_time}"
        ):

            st.write(
                f"**URL:** {scan_url}"
            )

            st.write(
                f"**Scan Time:** {scan_time}"
            )

            st.write(
                f"**HTTP Status:** "
                f"{status_code}"
            )

            st.write(
                f"**HTTPS:** "
                f"{'Enabled' if https else 'Not detected'}"
            )

            st.write(
                f"**Server:** "
                f"{server or 'Not disclosed'}"
            )


# =====================================
# SECURITY DASHBOARD
# =====================================

st.divider()

st.header(
    "📊 Security Dashboard"
)

history = get_scan_history()


if history:

    import pandas as pd

    # =====================================
    # DATAFRAME
    # =====================================

    df = pd.DataFrame(
        history,
        columns=[
            "ID",
            "URL",
            "Scan Time",
            "Status Code",
            "HTTPS",
            "Server"
        ]
    )


    # =====================================
    # DASHBOARD METRICS
    # =====================================

    total_scans = len(df)

    https_scans = int(
        df["HTTPS"].sum()
    )

    http_scans = (
        total_scans - https_scans
    )


    col1, col2, col3 = st.columns(3)


    with col1:

        st.metric(
            "Total Scans",
            total_scans
        )


    with col2:

        st.metric(
            "HTTPS Scans",
            https_scans
        )


    with col3:

        st.metric(
            "Non-HTTPS",
            http_scans
        )


    # =====================================
    # HTTPS CHART
    # =====================================

    st.subheader(
        "🔐 HTTPS Overview"
    )

    chart_data = pd.DataFrame({
        "Status": [
            "HTTPS Enabled",
            "HTTPS Not Detected"
        ],
        "Count": [
            https_scans,
            http_scans
        ]
    })


    st.bar_chart(
        chart_data.set_index("Status")
    )


    # =====================================
    # STATUS CODE ANALYSIS
    # =====================================

    st.subheader(
        "🌐 HTTP Status Codes"
    )

    status_data = (
        df["Status Code"]
        .value_counts()
        .sort_index()
    )


    st.bar_chart(
        status_data
    )


    # =====================================
    # RECENT SCANS
    # =====================================

    st.subheader(
        "🕒 Recent Scans"
    )

    display_df = df[
        [
            "URL",
            "Scan Time",
            "Status Code",
            "HTTPS",
            "Server"
        ]
    ]


    st.dataframe(
        display_df,
        use_container_width=True
    )


    # =====================================
    # SECURITY SCORE
    # =====================================

    st.divider()

    st.subheader(
        "🛡️ Security Score"
    )


    # Latest scan
    latest_url = df.iloc[0]["URL"]

    latest_scan = analyze_website(
        latest_url
    )


    if "error" not in latest_scan:

        total_checks = 0
        passed_checks = 0
        warnings = 0
        reviews = 0


        # =================================
        # SECURITY HEADERS
        # =================================

        for info in latest_scan[
            "security_headers"
        ].values():

            total_checks += 1

            if info["status"] == "PASS":

                passed_checks += 1

            else:

                warnings += 1


        # =================================
        # CORS
        # =================================

        total_checks += 1

        if latest_scan["cors"]["status"] == "PASS":

            passed_checks += 1

        elif latest_scan["cors"]["status"] == "REVIEW":

            reviews += 1


        # =================================
        # INFORMATION EXPOSURE
        # =================================

        for finding in latest_scan[
            "information_exposure"
        ]:

            total_checks += 1

            if finding["status"] == "PASS":

                passed_checks += 1

            else:

                reviews += 1


        # =================================
        # CALCULATE SCORE
        # =================================

        if total_checks > 0:

            score = round(
                (
                    passed_checks
                    / total_checks
                ) * 100
            )

        else:

            score = 0


        # =================================
        # SCORE DISPLAY
        # =================================

        st.metric(
            "Security Score",
            f"{score} / 100"
        )


        col1, col2, col3 = st.columns(3)


        with col1:

            st.metric(
                "PASS",
                passed_checks
            )


        with col2:

            st.metric(
                "WARN",
                warnings
            )


        with col3:

            st.metric(
                "REVIEW",
                reviews
            )


        # =================================
        # FINDINGS SUMMARY
        # =================================

        st.subheader(
            "📋 Findings Summary"
        )


        # Security headers
        for header, info in latest_scan[
            "security_headers"
        ].items():

            if info["status"] != "PASS":

                st.warning(
                    f"⚠️ {header}: "
                    f"{info['value']}"
                )


        # CORS
        cors = latest_scan["cors"]

        if cors["status"] == "REVIEW":

            st.warning(
                "⚠️ CORS: "
                + cors["message"]
            )


        # Information exposure
        for finding in latest_scan[
            "information_exposure"
        ]:

            if finding["status"] == "REVIEW":

                st.warning(
                    f"⚠️ {finding['name']}: "
                    f"{finding['value']}"
                )


        # =================================
        # PDF SECURITY REPORT
        # =================================

        st.divider()

        st.subheader(
            "📄 Professional Security Report"
        )

        st.write(
            "Generate a PDF report containing "
            "the scan results, security score, "
            "headers, cookies, CORS and "
            "information exposure findings."
        )


        try:

            pdf_file = create_security_report(
                latest_scan,
                score
            )


            st.download_button(
                label="⬇️ Download PDF Security Report",
                data=pdf_file,
                file_name="security_report.pdf",
                mime="application/pdf"
            )

        except Exception as error:

            st.error(
                "Could not generate PDF report."
            )

            st.code(
                str(error)
            )


    else:

        st.warning(
            "Unable to calculate security score."
        )


else:

    st.info(
        "Run at least one scan to display "
        "dashboard statistics."
    )