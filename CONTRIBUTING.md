# Contributing to Reflectra

Thank you for your interest in contributing to **Reflectra**! Contributions from the security research and developer community are welcome.

---

## Code of Conduct

Please adhere to standard open source community guidelines and maintain respectful, constructive interactions.

## Ground Rules & Scope

1. **Safety & Ethics First**: Reflectra is built exclusively for authorized penetration testing, security assessments, bug bounty programs, and educational research. PRs adding automated malicious exploitation or weaponized attack chains will be rejected.
2. **Quality & Test Coverage**: Any new feature, parser adjustment, or bug fix must include corresponding tests in `tests/test_unit.py` or `tests/test_integration_probe.py`.
3. **No Flaky Tests**: Tests must run deterministically. Use local mock servers or the provided `fixture_server.py`.
4. **Code Cleanliness**: Follow PEP 8 guidelines and type hinting conventions.

---

## Local Development Workflow

### 1. Fork & Clone

```bash
git clone https://github.com/pratik-khairnar-sec/Reflectra.git
cd Reflectra
```

### 2. Set Up Virtual Environment

```bash
python3 -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
```

### 3. Install in Editable Mode

```bash
pip install -r requirements.txt
pip install -e ".[dev]"
```

### 4. Run the Test Suite

```bash
python -m pytest tests/test_unit.py tests/test_integration_probe.py -v
```

---

## Submitting Pull Requests

1. Create a descriptive feature branch:
   ```bash
   git checkout -b feature/improved-dom-sink-parsing
   ```
2. Commit your changes with clear messages:
   ```bash
   git commit -m "feat(sinks): add evaluation for modern Web API sinks"
   ```
3. Push to your fork:
   ```bash
   git push origin feature/improved-dom-sink-parsing
   ```
4. Open a Pull Request against the `main` branch with details on what changed, why, and test verification output.
