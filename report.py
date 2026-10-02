from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def create_security_report(result, score):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    heading_style = styles["Heading2"]
    normal_style = styles["BodyText"]

    story = []

    # =====================================
    # TITLE
    # =====================================

    story.append(
        Paragraph(
            "Web Security Analyzer Report",
            title_style
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Authorized defensive security configuration assessment",
            normal_style
        )
    )

    story.append(Spacer(1, 15))

    # =====================================
    # BASIC INFORMATION
    # =====================================

    story.append(
        Paragraph(
            "1. Scan Information",
            heading_style
        )
    )

    scan_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    basic_data = [
        ["Website", result["url"]],
        ["Scan Time", scan_time],
        ["HTTP Status", str(result["status_code"])],
        [
            "HTTPS",
            "Enabled"
            if result["https"]
            else "Not detected"
        ],
        [
            "Server",
            result["server"]
            or "Not disclosed"
        ],
        [
            "Security Score",
            f"{score} / 100"
        ]
    ]

    basic_table = Table(
        basic_data,
        colWidths=[130, 360]
    )

    basic_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ])
    )

    story.append(basic_table)

    story.append(Spacer(1, 20))

    # =====================================
    # SECURITY HEADERS
    # =====================================

    story.append(
        Paragraph(
            "2. Security Headers",
            heading_style
        )
    )

    header_data = [
        ["Header", "Status", "Value"]
    ]

    for header, info in result[
        "security_headers"
    ].items():

        header_data.append([
            header,
            info["status"],
            info["value"]
        ])

    header_table = Table(
        header_data,
        colWidths=[180, 70, 240],
        repeatRows=1
    )

    header_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )

    story.append(header_table)

    story.append(Spacer(1, 20))

    # =====================================
    # COOKIE SECURITY
    # =====================================

    story.append(
        Paragraph(
            "3. Cookie Security",
            heading_style
        )
    )

    if result["cookies"]:

        cookie_data = [
            [
                "Cookie",
                "Secure",
                "HttpOnly",
                "SameSite"
            ]
        ]

        for cookie in result["cookies"]:

            cookie_data.append([
                cookie["name"],
                "Yes"
                if cookie["secure"]
                else "No",
                "Yes"
                if cookie["httponly"]
                else "No",
                str(cookie["samesite"])
            ])

        cookie_table = Table(
            cookie_data,
            colWidths=[150, 80, 80, 120],
            repeatRows=1
        )

        cookie_table.setStyle(
            TableStyle([
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
            ])
        )

        story.append(cookie_table)

    else:

        story.append(
            Paragraph(
                "No cookies were returned by the initial request.",
                normal_style
            )
        )

    story.append(Spacer(1, 20))

    # =====================================
    # CORS
    # =====================================

    story.append(
        Paragraph(
            "4. CORS Configuration",
            heading_style
        )
    )

    cors = result["cors"]

    cors_data = [
        [
            "Property",
            "Value"
        ],
        [
            "Status",
            cors["status"]
        ],
        [
            "Allow-Origin",
            cors["origin"]
        ],
        [
            "Allow-Credentials",
            cors["credentials"]
        ],
        [
            "Allow-Methods",
            cors["methods"]
        ],
        [
            "Allow-Headers",
            cors["headers"]
        ]
    ]

    cors_table = Table(
        cors_data,
        colWidths=[180, 310]
    )

    cors_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
        ])
    )

    story.append(cors_table)

    story.append(Spacer(1, 20))

    # =====================================
    # INFORMATION EXPOSURE
    # =====================================

    story.append(
        Paragraph(
            "5. Information Exposure",
            heading_style
        )
    )

    exposure_data = [
        [
            "Finding",
            "Status",
            "Value"
        ]
    ]

    for finding in result[
        "information_exposure"
    ]:

        exposure_data.append([
            finding["name"],
            finding["status"],
            finding["value"]
        ])

    exposure_table = Table(
        exposure_data,
        colWidths=[180, 70, 240],
        repeatRows=1
    )

    exposure_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
        ])
    )

    story.append(exposure_table)

    story.append(Spacer(1, 20))

    # =====================================
    # SUMMARY
    # =====================================

    story.append(
        Paragraph(
            "6. Summary",
            heading_style
        )
    )

    story.append(
        Paragraph(
            f"The analyzed website received a "
            f"configuration score of {score} out of 100 "
            f"based on the checks performed by this project.",
            normal_style
        )
    )

    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "This report is intended for authorized "
            "defensive security assessment and "
            "configuration review.",
            normal_style
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer