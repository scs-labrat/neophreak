
# NeoPhreak

![NeoPhreak Logo](https://github.com/yourusername/NeoPhreak/raw/main/assets/logo.png)

**NeoPhreak** is a comprehensive TelcoSecure Testing Platform designed to facilitate robust testing, discovery, and analysis of telecommunications protocols and targets. Renamed from the original TelcoSecure Testing Platform, NeoPhreak offers an enhanced suite of tools and features tailored for telecom security professionals, network engineers, and enthusiasts.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgments](#acknowledgments)

## Features

- **Protocol Testing**: Supports Diameter, SCCP, and GTP protocols with customizable configurations.
- **Target Discovery**: Efficiently discovers telecom targets using advanced scanning techniques.
- **Live Output Terminal**: Real-time monitoring of ongoing tests and scans.
- **Results Parsing**: Parses discovery results into organized tables with detailed protocol information.
- **Shodan Integration**: Queries Shodan for additional insights on discovered IPs.
- **Geolocation Mapping**: Visualizes target locations on an interactive map using Leaflet.js.
- **Export Functionality**: Export results in CSV, JSON, and PDF formats for further analysis.
- **User-Friendly Interface**: Intuitive UI built with Bootstrap for seamless navigation and operation.
- **Dependency Checks**: Ensures all necessary dependencies are installed before running tests.
- **Pagination Controls**: Manage large sets of Shodan results with easy-to-use pagination.

## Installation

### Prerequisites

- **Python 3.8+**: Ensure Python is installed on your system. [Download Python](https://www.python.org/downloads/)
- **Git**: Version control system to clone the repository. [Download Git](https://git-scm.com/downloads)
- **Node.js & npm** (Optional): If you plan to work with front-end assets. [Download Node.js](https://nodejs.org/)

### Clone the Repository

```bash
git clone https://github.com/yourusername/NeoPhreak.git
cd NeoPhreak
```

### Create a Virtual Environment

It's recommended to use a virtual environment to manage dependencies.

```bash
python -m venv venv
```

Activate the virtual environment:

- **Windows:**
  ```bash
  venv\Scripts\activate
  ```
- **macOS/Linux:**
  ```bash
  source venv/bin/activate
  ```

### Install Dependencies

```bash
pip install -r requirements.txt
```

*If your project includes front-end dependencies, navigate to the front-end directory and install them:*

```bash
cd frontend
npm install
```

## Usage

### Running the Application

Ensure your virtual environment is activated.

```bash
python app.py
```

*If using a front-end build tool:*

```bash
cd frontend
npm start
```

### Accessing NeoPhreak

Open your web browser and navigate to:

```
http://localhost:5000
```

### Features Walkthrough

1. **Testing Configuration**: 
   - Select the desired protocol (Diameter, SCCP, GTP).
   - Enter a valid MSISDN (10-15 numeric characters).
   - Upload a file containing target IPs (`.txt` or `.csv`).

2. **Control Panel**:
   - **Start Scan**: Initiates the discovery of telecom targets.
   - **Stop Scan**: Halts the ongoing scan.
   - **Parse Results**: Processes and displays the discovery results.
   - **Check Dependencies**: Verifies all necessary dependencies are installed.
   - **Query Shodan**: Retrieves additional information on discovered IPs from Shodan.
   - **Export to CSV**: Downloads the results in CSV format.

3. **Live Output Terminal**: 
   - Monitors real-time logs and outputs of ongoing operations.

4. **Discovery Results**:
   - Displays a table of discovered IPs with detailed protocol information.
   - Visualizes target locations on an interactive geolocation map.
   - Provides export options in CSV, JSON, and PDF formats.

## Configuration

### Environment Variables

Create a `.env` file in the root directory to manage configuration settings.

```env
# .env file

# Server Configuration
HOST=0.0.0.0
PORT=5000
DEBUG=True

# Shodan API Configuration
SHODAN_API_KEY=your_shodan_api_key_here

# Other configurations as needed
```

*Ensure to replace `your_shodan_api_key_here` with your actual Shodan API key.*

### API Keys

- **Shodan API**: Required for querying Shodan. [Get a Shodan API Key](https://account.shodan.io/)

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

### Steps to Contribute

1. **Fork the Project**: Click the "Fork" button at the top right of the repository page.
2. **Clone Your Fork**:
   ```bash
   git clone https://github.com/yourusername/NeoPhreak.git
   cd NeoPhreak
   ```
3. **Create a Branch**:
   ```bash
   git checkout -b feature/YourFeatureName
   ```
4. **Make Changes**: Implement your feature or bug fix.
5. **Commit Changes**:
   ```bash
   git commit -m "Add your message here"
   ```
6. **Push to Fork**:
   ```bash
   git push origin feature/YourFeatureName
   ```
7. **Open a Pull Request**: Navigate to your fork on GitHub and click the "New pull request" button.

### Guidelines

- Follow the [PEP 8](https://pep8.org/) style guide for Python code.
- Ensure all new features are accompanied by relevant tests.
- Update the documentation (`README.md`, inline comments) as necessary.
- Discuss major changes via issues before implementing them.

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

**Your Name**  
Project Link: [https://github.com/yourusername/NeoPhreak](https://github.com/yourusername/NeoPhreak)

## Acknowledgments

- [Bootstrap](https://getbootstrap.com/) - For the responsive UI framework.
- [Leaflet.js](https://leafletjs.com/) - For the interactive geolocation maps.
- [Shodan](https://www.shodan.io/) - For providing comprehensive internet intelligence.
- [jsPDF](https://github.com/parallax/jsPDF) - For PDF generation capabilities.
- [GitHub](https://github.com/) - For hosting the repository and facilitating collaboration.

---

## Download NeoPhreak

You can download the latest version of NeoPhreak from the [Releases](https://github.com/scs-labrat/NeoPhreak/releases) page.

[![Download NeoPhreak](https://img.shields.io/badge/Download-NeoPhreak%20v1.0-blue)](https://github.com/scs-labrat/NeoPhreak/releases/download/v1.0/NeoPhreak.zip)