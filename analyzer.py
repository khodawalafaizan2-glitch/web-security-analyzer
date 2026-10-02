import requests
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Helps prevent XSS and unauthorized content loading.",

    "Strict-Transport-Security":
        "Forces browsers to use HTTPS.",

    "X-Content-Type-Options":
        "Prevents MIME-type sniffing.",

    "X-Frame-Options":
        "Helps prevent clickjacking.",

    "Referrer-Policy":
        "Controls how much referrer information is sent.",

    "Permissions-Policy":
        "Controls access to browser features."
}


def analyze_cookies(response):

    cookies = []

    for cookie in response.cookies:

        secure = cookie.secure

        rest = getattr(cookie, "_rest", {})

        httponly = any(
            key.lower() == "httponly"
            for key in rest
        )

        samesite = None

        for key, value in rest.items():

            if key.lower() == "samesite":
                samesite = value

        cookies.append({
            "name": cookie.name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite or "Not detected"
        })

    return cookies


def analyze_cors(response):

    origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    credentials = response.headers.get(
        "Access-Control-Allow-Credentials"
    )

    methods = response.headers.get(
        "Access-Control-Allow-Methods"
    )

    headers = response.headers.get(
        "Access-Control-Allow-Headers"
    )

    if origin is None:

        status = "INFO"

        message = (
            "No Access-Control-Allow-Origin "
            "header detected in the normal response."
        )

    elif origin == "*":

        status = "REVIEW"

        message = (
            "Wildcard CORS origin detected. "
            "Review whether public cross-origin access "
            "is actually required."
        )

    else:

        status = "PASS"

        message = (
            "A specific CORS origin is configured."
        )

    return {
        "status": status,
        "origin": origin or "Not detected",
        "credentials": credentials or "Not detected",
        "methods": methods or "Not detected",
        "headers": headers or "Not detected",
        "message": message
    }


def analyze_information_exposure(response):

    findings = []

    # Server header
    server = response.headers.get("Server")

    if server:

        findings.append({
            "name": "Server Header",
            "status": "REVIEW",
            "value": server,
            "description":
                "The response discloses server information."
        })

    else:

        findings.append({
            "name": "Server Header",
            "status": "PASS",
            "value": "Not disclosed",
            "description":
                "Server header was not detected."
        })


    # X-Powered-By
    powered_by = response.headers.get(
        "X-Powered-By"
    )

    if powered_by:

        findings.append({
            "name": "X-Powered-By",
            "status": "REVIEW",
            "value": powered_by,
            "description":
                "This header may disclose application "
                "technology information."
        })

    else:

        findings.append({
            "name": "X-Powered-By",
            "status": "PASS",
            "value": "Not disclosed",
            "description":
                "X-Powered-By header was not detected."
        })


    # Technology/version indicators
    version_headers = [
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator"
    ]

    for header in version_headers:

        value = response.headers.get(header)

        if value:

            findings.append({
                "name": header,
                "status": "REVIEW",
                "value": value,
                "description":
                    "A technology or version indicator "
                    "was detected."
            })

        else:

            findings.append({
                "name": header,
                "status": "PASS",
                "value": "Not detected",
                "description":
                    "No value was detected."
            })


    return findings


def analyze_website(url):

    if not url.startswith(("http://", "https://")):

        url = "https://" + url

    result = {
        "url": url,
        "status_code": None,
        "https": False,
        "server": None,
        "headers": {},
        "security_headers": {},
        "cookies": [],
        "cors": {},
        "information_exposure": []
    }

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        result["status_code"] = response.status_code

        result["https"] = (
            urlparse(response.url).scheme == "https"
        )

        result["server"] = response.headers.get(
            "Server"
        )

        result["headers"] = dict(response.headers)


        # Security headers
        for header, description in SECURITY_HEADERS.items():

            value = response.headers.get(header)

            if value:

                result["security_headers"][header] = {
                    "status": "PASS",
                    "value": value,
                    "description": description
                }

            else:

                result["security_headers"][header] = {
                    "status": "WARN",
                    "value": "Not detected",
                    "description": description
                }


        # Cookies
        result["cookies"] = analyze_cookies(response)


        # CORS
        result["cors"] = analyze_cors(response)


        # Information exposure
        result["information_exposure"] = (
            analyze_information_exposure(response)
        )


        return result


    except requests.RequestException as error:

        result["error"] = str(error)

        return result