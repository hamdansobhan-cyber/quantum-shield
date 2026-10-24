# Quantum Shield

A web-based network vulnerability scanning and security analysis system developed to make security assessments easier through a user-friendly web interface.

## Overview

Quantum Shield integrates security tools into a web application to help users perform network reconnaissance and vulnerability assessments on authorised targets.

## Technologies Used

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Database:** SQLite
- **Security Tools:** Nmap, Nikto

## Key Features

- Web-based dashboard
- Network scanning and reconnaissance
- Vulnerability scanning integration
- Risk classification
- Scan history and results management
- Security report generation

*Features listed above should match the functionality implemented in the current version of the project.*

## Project Structure

- `app.py` — Main Flask application
- `database.py` — Database operations
- `requirements.txt` — Python dependencies
- `dashboard.html` — Dashboard interface
- `index.html` — Main application page
- `login.html` — Login interface

## Getting Started

1. Install Python 3.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Install and configure the external scanning tools required by the application.
4. Review the configuration and database setup.
5. Run the Flask application using `python app.py`.

Follow the configuration requirements in the source code before running the application.

## Security Notice

Use this application only on systems and networks you own or have explicit permission to assess. Review target validation, command execution, authentication, and database security before deployment.

## Author

Hamdan Sobhan  
Computer Science (Cybersecurity), Universiti Tenaga Nasional (UNITEN)


## Application Screenshots

### Login Page
![Quantum Shield Login](screenshots/login.image.png)

### Two-Factor Authentication
![Two-Factor Authentication](screenshots/two factor authentication.png)

### Dashboard
![Quantum Shield Dashboard](screenshots/dashboard.png)

### Scanning Progress
![Scanning Progress](screenshots/scan-progress.png)

### Scan Results
![Scan Results](screenshots/scan-results.png)

