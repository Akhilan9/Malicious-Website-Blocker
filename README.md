# Malicious Website Scanner and Blocker

A Windows-based cybersecurity desktop application built with Python and Tkinter that allows users to scan URLs for malicious activity and locally block access to dangerous domains.

## Features

- **Gmail Registration:** Securely register and hash your email address using SHA-256.
- **Two-Factor Authentication (2FA):** Protected actions like blocking/unblocking require a randomly generated password sent to your registered email.
- **Website Reputation Scanning:** Integrates with the VirusTotal API to determine if a website is safe, suspicious, or malicious based on reports from over 70 security vendors.
- **Local Website Blocking:** Safely modifies the Windows `hosts` file to redirect malicious domains to localhost (`127.0.0.1`), effectively preventing access.
- **Website Unblocking:** Easily restore access by removing application-specific entries from the `hosts` file without affecting other custom configurations.
- **Project Information Server:** Starts a local HTTP daemon to serve project documentation and architectural details.

## Architecture and Technologies

- **Backend:** Python 3.x
- **GUI:** Tkinter / ttk (Dark modern theme)
- **External API:** VirusTotal API v3 (via `requests`)
- **Security:** `hashlib` for SHA-256, SMTP with `email.mime` for 2FA password delivery
- **System Integration:** Windows `hosts` file manipulation with automatic backups
- **Local Server:** `http.server`, `socketserver`, and `threading`

## Installation and Setup

### 1. Prerequisites

- Windows Operating System (Required for `hosts` file modification)
- Python 3.x installed (with `pip`)
- Administrator privileges (for blocking/unblocking websites)

### 2. Clone the Repository

```bash
# If using git
git clone https://github.com/yourusername/malicious-website-blocker.git
cd malicious-website-blocker
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment Variables

Create a `.env` file in the root directory. You can use `.env.example` as a template.

```env
# VirusTotal API Key for scanning URLs
# Get one for free at https://www.virustotal.com/
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Gmail SMTP Configuration for sending authentication passwords
# Use an App Password if 2FA is enabled on your Google account
SMTP_EMAIL=your_email@gmail.com
SMTP_PASSWORD=your_app_password_here
```

**Security Note:** Never hardcode your API keys or passwords in the source code. The `.env` file should not be committed to version control.

## Running the Application

To start the application, run:

```bash
python main.py
```

### Workflow

1. **Register:** Click "Register Gmail" and enter your email address. It will be stored securely as a SHA-256 hash.
2. **Scan:** Enter a URL (e.g., `example.com`) and click "Check Website". The app will query VirusTotal and display the security results.
3. **Block:** Click "Block Website". You will be prompted to authenticate. Enter the password sent to your email. If successful, the domain is added to your Windows `hosts` file.
4. **Unblock:** Click "Unblock Website" and authenticate to remove the restriction.
5. **Info:** Click "Project Info" to launch the local web server and open the documentation page in your browser.

## Security Considerations

- **Hosts File Backup:** Every time a block or unblock action occurs, the application creates a backup of the `hosts` file (`C:\Windows\System32\drivers\etc\hosts.backup_YYYYMMDD_HHMMSS`).
- **Data Protection:** The Gmail address is never stored in plain text. Only the SHA-256 hash is saved locally in `registered_gmail_hash.txt`.

## Testing

Run the included unit tests using:

```bash
python -m unittest discover tests
```

Tests include validations for:
- Email parsing and validation
- SHA-256 hashing logic
- Simulated VirusTotal API responses (mocked to prevent API quota usage)
- Simulated hosts file reading

## Troubleshooting

- **Permission Denied:** Ensure you start the application or command prompt as Administrator, otherwise modifying the `hosts` file will fail.
- **Email Not Sending:** If using Gmail with 2FA, you must generate an "App Password" rather than using your standard account password.
- **API Errors:** Ensure your VirusTotal API key is valid and you have not exceeded the free tier rate limits (usually 4 requests per minute).

## Future Enhancements

- AI/ML-based URL classification
- Categorized blocking (e.g., adult content, known trackers)
- Centralized threat intelligence integrations
- Real-time network dashboard
