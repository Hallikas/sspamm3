# Sspamm3 - Semi's Spam Milter

**Sspamm3** (Semi's Spam Milter) is a modern, Python 3-based milter for filtering spam emails using regex-based rules. It integrates with mail servers like Postfix, offering flexible filtering and JSON-based logging. This is a complete rewrite of the original Sspamm, designed for performance, security, and maintainability.

## Key Features

- **Regex-Based Filtering**: Define rules using regular expressions for domains, headers, and content.
- **Domain-Specific Rules**: Apply custom tests per domain or a default policy.
- **JSON Logging**: Securely store email metadata in JSON format for offline testing.
- **Thread-Safe**: Handles concurrent email processing.

## Installation

### Prerequisites
- Python 3.6+
- `pymilter`
- Postfix or compatible mail server
- Docker (optional, for testing)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/Hallikas/sspamm3.git
   cd sspamm3
   ```
2. Install dependencies:
   ```bash
   pip install pymilter
   ```
3. Configure Postfix in `/etc/postfix/main.cf`:
   ```ini
   smtpd_milters = unix:/var/run/sspamm3.sock
   ```
4. Copy the example configuration:
   ```bash
   cp sspamm3.conf.example /etc/sspamm3.conf
   ```
5. Start the milter:
   ```bash
   python3 sspamm3.py --config /etc/sspamm3.conf
   ```

### Docker Testing
Build and run a Docker container for testing:
```bash
docker build -t sspamm3 .
docker run -v $(pwd)/data:/data -p 8890:8890 sspamm3
```

## Configuration

Edit `sspamm3.conf` to define filtering rules. See `sspamm3.conf.example` for details.

## Usage

- **Live Filtering**: Process emails via the milter interface.
- **Offline Testing**: Test JSON files with:
  ```bash
  python3 sspamm3.py --test /app/example.json
  ```

## Contributing

Fork, create a feature branch, and submit a pull request. See [CONTRIBUTING.md](#) for details.

## License

MIT License

## Contact

Open an issue or email sspamm@hallikas.com.

*Last updated: July 27, 2025*
