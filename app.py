from flask import Flask, render_template, request
import platform
import socket
import os
import subprocess
import uuid
from datetime import datetime


app = Flask(__name__)


# ==================================================
# CHECK WINDOWS FIREWALL
# ==================================================

def check_firewall():

    try:

        command = [
            "powershell",
            "-Command",
            "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = result.stdout.strip().lower()

        if not output:
            return None

        if "false" in output:
            return False

        return True

    except Exception:
        return None


# ==================================================
# CHECK LOCAL OPEN PORTS
# ==================================================

def check_open_ports():

    ports = [21, 22, 80, 443, 3389]

    open_ports = []

    for port in ports:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(0.5)

            result = sock.connect_ex(
                ("127.0.0.1", port)
            )

            sock.close()

            if result == 0:
                open_ports.append(port)

        except Exception:
            pass

    return open_ports


# ==================================================
# CALCULATE SECURITY SCORE
# ==================================================

def calculate_security_score():

    score = 100

    open_ports = check_open_ports()

    if len(open_ports) == 0:
        score -= 0

    elif len(open_ports) == 1:
        score -= 10

    elif len(open_ports) == 2:
        score -= 20

    else:
        score -= 30

    firewall_enabled = check_firewall()

    if firewall_enabled is True:
        score -= 0

    elif firewall_enabled is False:
        score -= 30

    else:
        score -= 10

    if score < 0:
        score = 0

    if score > 100:
        score = 100

    if score >= 80:
        risk = "LOW"

    elif score >= 50:
        risk = "MEDIUM"

    else:
        risk = "HIGH"

    return score, risk, len(open_ports), firewall_enabled


# ==================================================
# HOME / DASHBOARD
# ==================================================

@app.route("/")
def home():

    return render_template("index.html")


# ==================================================
# SYSTEM INFORMATION
# ==================================================

@app.route("/system-info")
def system_info():

    system = platform.system()

    version = platform.version()

    processor = platform.processor()

    architecture = platform.machine()

    hostname = socket.gethostname()

    return render_template(
        "system_info.html",
        system=system,
        version=version,
        processor=processor,
        architecture=architecture,
        hostname=hostname
    )


# ==================================================
# NETWORK CONFIGURATION
# ==================================================

@app.route("/network-config")
def network_config():

    # ----------------------------------------------
    # COMPUTER NAME
    # ----------------------------------------------

    hostname = socket.gethostname()


    # ----------------------------------------------
    # LOCAL IPv4 ADDRESS
    # ----------------------------------------------

    try:

        local_ip = socket.gethostbyname(hostname)

    except Exception:

        local_ip = "Unable to detect"


    # ----------------------------------------------
    # MAC ADDRESS
    # ----------------------------------------------

    try:

        mac_number = uuid.getnode()

        mac_address = ":".join(
            f"{(mac_number >> shift) & 0xff:02X}"
            for shift in range(40, -1, -8)
        )

    except Exception:

        mac_address = "Unable to detect"


    # ----------------------------------------------
    # DEFAULT GATEWAY
    # ----------------------------------------------

    try:

        gateway_result = subprocess.run(
            [
                "powershell",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 -ExpandProperty NextHop)"
            ],
            capture_output=True,
            text=True
        )

        gateway = gateway_result.stdout.strip()

        if not gateway:

            gateway = "Unable to detect"

    except Exception:

        gateway = "Unable to detect"


    # ----------------------------------------------
    # DNS SERVER
    # ----------------------------------------------

    try:

        dns_result = subprocess.run(
            [
                "powershell",
                "-Command",
                "(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | Select-Object -First 1 -ExpandProperty ServerAddresses)"
            ],
            capture_output=True,
            text=True
        )

        dns_server = dns_result.stdout.strip()

        if not dns_server:

            dns_server = "Unable to detect"

        else:

            dns_server = dns_server.splitlines()[0].strip()

    except Exception:

        dns_server = "Unable to detect"


    # ----------------------------------------------
    # NETWORK ADAPTER
    # ----------------------------------------------

    try:

        powershell_command = (
            "(Get-NetIPConfiguration | "
            "Where-Object {$_.IPv4Address.IPAddress -eq '"
            + local_ip +
            "'} | "
            "Select-Object -ExpandProperty InterfaceAlias)"
        )

        adapter_result = subprocess.run(
            [
                "powershell",
                "-Command",
                powershell_command
            ],
            capture_output=True,
            text=True
        )

        network_adapter = adapter_result.stdout.strip()

        if not network_adapter:

            network_adapter = "Unable to detect"

    except Exception:

        network_adapter = "Unable to detect"


    # ----------------------------------------------
    # DHCP STATUS
    # ----------------------------------------------

    try:

        dhcp_result = subprocess.run(
            [
                "powershell",
                "-Command",
                "(Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.ConnectionState -eq 'Connected'} | Select-Object -First 1 -ExpandProperty Dhcp)"
            ],
            capture_output=True,
            text=True
        )

        dhcp_status = dhcp_result.stdout.strip().upper()

        if dhcp_status not in [
            "ENABLED",
            "DISABLED"
        ]:

            dhcp_status = "Unable to detect"

    except Exception:

        dhcp_status = "Unable to detect"


    # ----------------------------------------------
    # IPv6 ADDRESS
    # ----------------------------------------------

    try:

        ipv6_result = subprocess.run(
            [
                "powershell",
                "-Command",
                "(Get-NetIPAddress -AddressFamily IPv6 | Where-Object {$_.IPAddress -notlike 'fe80*' -and $_.IPAddress -ne '::1'} | Select-Object -First 1 -ExpandProperty IPAddress)"
            ],
            capture_output=True,
            text=True
        )

        ipv6_address = ipv6_result.stdout.strip()

        if not ipv6_address:

            ipv6_address = "Not detected"

    except Exception:

        ipv6_address = "Unable to detect"


    # ----------------------------------------------
    # SEND DATA TO HTML
    # ----------------------------------------------

    return render_template(
        "network_config.html",
        hostname=hostname,
        local_ip=local_ip,
        mac_address=mac_address,
        gateway=gateway,
        dns_server=dns_server,
        network_adapter=network_adapter,
        dhcp_status=dhcp_status,
        ipv6_address=ipv6_address
    )


# ==================================================
# OPEN PORT CHECK
# ==================================================

@app.route("/open-ports")
def open_ports():

    ports = [
        21,
        22,
        80,
        443,
        3389
    ]

    results = []

    for port in ports:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(0.5)

            result = sock.connect_ex(
                ("127.0.0.1", port)
            )

            sock.close()

            if result == 0:

                status = "OPEN"

            else:

                status = "CLOSED"

        except Exception:

            status = "ERROR"

        results.append({
            "port": port,
            "status": status
        })

    return render_template(
        "open_ports.html",
        results=results
    )


# ==================================================
# SECURITY SCORE
# ==================================================

@app.route("/security-score")
def security_score():

    score, risk, open_ports_count, firewall_enabled = calculate_security_score()

    if firewall_enabled is True:

        firewall_status = "ENABLED"

    elif firewall_enabled is False:

        firewall_status = "DISABLED"

    else:

        firewall_status = "UNKNOWN"

    return render_template(
        "security_score.html",
        score=score,
        risk=risk,
        open_ports=open_ports_count,
        firewall_status=firewall_status
    )


# ==================================================
# PASSWORD STRENGTH ANALYZER
# ==================================================

@app.route("/password-analyzer", methods=["GET", "POST"])
def password_analyzer():

    result = None

    score = 0

    length = 0

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        length = len(password)

        has_upper = any(
            char.isupper()
            for char in password
        )

        has_lower = any(
            char.islower()
            for char in password
        )

        has_digit = any(
            char.isdigit()
            for char in password
        )

        has_special = any(
            not char.isalnum()
            for char in password
        )

        if length >= 8:

            score += 25

        if has_upper:

            score += 25

        if has_lower:

            score += 20

        if has_digit:

            score += 15

        if has_special:

            score += 15

        if score >= 80:

            result = "STRONG"

        elif score >= 50:

            result = "MEDIUM"

        else:

            result = "WEAK"

    return render_template(
        "password_analyzer.html",
        result=result,
        score=score,
        length=length
    )


# ==================================================
# FIREWALL / NGFW CHECK
# ==================================================

@app.route("/firewall")
def firewall():

    firewall_enabled = check_firewall()

    if firewall_enabled is True:

        firewall_status = "ENABLED"

        protection = "ACTIVE"

    elif firewall_enabled is False:

        firewall_status = "DISABLED"

        protection = "INACTIVE"

    else:

        firewall_status = "UNKNOWN"

        protection = "UNKNOWN"

    return render_template(
        "firewall.html",
        firewall_status=firewall_status,
        protection=protection
    )


# ==================================================
# FILE PERMISSION SECURITY CHECK
# ==================================================

@app.route("/file-permission", methods=["GET", "POST"])
def file_permission():

    result = None

    if request.method == "POST":

        path = request.form.get(
            "path",
            ""
        ).strip()

        if os.path.exists(path):

            if os.path.isfile(path):

                item_type = "FILE"

            elif os.path.isdir(path):

                item_type = "FOLDER"

            else:

                item_type = "OTHER"

            read_access = os.access(
                path,
                os.R_OK
            )

            write_access = os.access(
                path,
                os.W_OK
            )

            score = 0

            if read_access:

                score += 50

            if write_access:

                score += 50

            if score == 100:

                risk = "LOW"

            elif score >= 50:

                risk = "MEDIUM"

            else:

                risk = "HIGH"

            result = {
                "path": path,
                "type": item_type,
                "read": "YES" if read_access else "NO",
                "write": "YES" if write_access else "NO",
                "score": score,
                "risk": risk
            }

        else:

            result = {
                "path": path,
                "type": "NOT FOUND",
                "read": "N/A",
                "write": "N/A",
                "score": 0,
                "risk": "UNKNOWN"
            }

    return render_template(
        "file_permissions.html",
        result=result
    )


# ==================================================
# PROFESSIONAL SECURITY REPORT
# ==================================================

@app.route("/report")
def report():

    # ----------------------------------------------
    # SYSTEM INFORMATION
    # ----------------------------------------------

    system = platform.system()

    version = platform.version()

    processor = platform.processor()

    architecture = platform.machine()

    hostname = socket.gethostname()


    # ----------------------------------------------
    # NETWORK INFORMATION
    # ----------------------------------------------

    try:

        local_ip = socket.gethostbyname(hostname)

    except Exception:

        local_ip = "Unable to detect"


    # ----------------------------------------------
    # OPEN PORTS
    # ----------------------------------------------

    open_ports = check_open_ports()

    open_ports_count = len(open_ports)


    # ----------------------------------------------
    # FIREWALL
    # ----------------------------------------------

    firewall_enabled = check_firewall()

    if firewall_enabled is True:

        firewall_status = "ENABLED"

    elif firewall_enabled is False:

        firewall_status = "DISABLED"

    else:

        firewall_status = "UNKNOWN"


    # ----------------------------------------------
    # SECURITY SCORE
    # ----------------------------------------------

    score, risk, _, _ = calculate_security_score()


    # ----------------------------------------------
    # DATE AND TIME
    # ----------------------------------------------

    scan_time = datetime.now().strftime(
        "%d %B %Y - %I:%M:%S %p"
    )


    # ----------------------------------------------
    # RECOMMENDATIONS
    # ----------------------------------------------

    recommendations = []

    if open_ports_count > 0:

        recommendations.append(
            "Review unnecessary open network ports."
        )

    else:

        recommendations.append(
            "No tested local ports were found open."
        )


    if firewall_enabled is False:

        recommendations.append(
            "Enable Windows Firewall."
        )

    elif firewall_enabled is True:

        recommendations.append(
            "Windows Firewall is currently enabled."
        )

    else:

        recommendations.append(
            "Verify Windows Firewall status manually."
        )


    if score >= 80:

        recommendations.append(
            "Continue following good cybersecurity practices."
        )

    elif score >= 50:

        recommendations.append(
            "Improve the security configuration of the system."
        )

    else:

        recommendations.append(
            "Immediate security improvements are recommended."
        )


    return render_template(
        "report.html",
        system=system,
        version=version,
        processor=processor,
        architecture=architecture,
        hostname=hostname,
        local_ip=local_ip,
        open_ports=open_ports,
        open_ports_count=open_ports_count,
        firewall_status=firewall_status,
        score=score,
        risk=risk,
        scan_time=scan_time,
        recommendations=recommendations
    )


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(debug=True)