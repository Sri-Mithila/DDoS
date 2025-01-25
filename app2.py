from flask import Flask, request, render_template, redirect, jsonify
import os
import platform
import subprocess
from threading import Lock

app = Flask(__name__)
active_ips = {}  # Dictionary to track requests per IP
ip_lock = Lock()
MAX_REQUESTS_PER_IP = 10  # Allow up to 10 requests per IP before redirecting to CAPTCHA
MAX_THRESHOLD = 50        # Example: 50% of max capacity


def ping_ip(ip):
    """Ping an IP address to check if it's live, cross-platform."""
    try:
        # Use appropriate ping command based on OS
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]  # Windows: 1 ping, 1s timeout
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]  # Unix/Linux: 1 ping, 1s timeout

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            # Check for "TTL=" in the output to confirm the response
            if "TTL=" in result.stdout or "ttl=" in result.stdout:
                return True
        return False
    except Exception as e:
        print(f"Ping command failed for IP {ip}: {e}")
        return False


@app.route("/", methods=["GET", "POST"])
def login():
    client_ip = request.remote_addr
    with ip_lock:
        # Track and update request count for this IP
        if client_ip not in active_ips:
            active_ips[client_ip] = 0
        active_ips[client_ip] += 1

        # Check if the number of requests has exceeded the threshold
        if active_ips[client_ip] > MAX_REQUESTS_PER_IP:
            return redirect("/captcha")  # Redirect to CAPTCHA if request count exceeds limit

        if not ping_ip(client_ip):
            return jsonify({"message": f"Fake or dead IP {client_ip} detected, rejected"}), 403

        if len(active_ips) > MAX_THRESHOLD:
            return redirect("/captcha")  # Redirect to CAPTCHA if server is overwhelmed

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == "admin" and password == "admin123":  # Example credentials
            return jsonify({"message": "Login successful!"})
        else:
            return jsonify({"message": "Invalid credentials!"}), 401
    return render_template("login.html")


@app.route("/captcha", methods=["GET", "POST"])
def captcha():
    if request.method == "POST":
        # Simulate CAPTCHA validation (replace with actual service integration).
        captcha_response = request.json.get("captcha")

        # Check if the CAPTCHA response is 'pass'
        if captcha_response == "pass":
            with ip_lock:
                # Reset the IP's request count after CAPTCHA is solved
                active_ips[request.remote_addr] = 0
            return jsonify({"message": "CAPTCHA validated successfully!"}), 200
        else:
            return jsonify({"message": "Invalid CAPTCHA!"}), 403

    return render_template("captcha.html")


@app.route("/cleanup")
def cleanup():
    """Clean up IPs (simulated periodic clean-up)."""
    with ip_lock:
        active_ips.clear()
    return jsonify({"message": "Active IPs cleared!"})


@app.before_request
def validate_request():
    """Filter irrelevant or suspicious requests."""
    if request.endpoint not in ["login", "captcha", "cleanup"]:
        return jsonify({"message": "Request blocked"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
