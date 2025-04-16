# Contributing to Hardware CWE Bug Detection Project

Thank you for your interest in contributing to this project! This document provides guidelines for contributing to the Hardware CWE Bug Detection project.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improvement:

1. Check if the issue already exists in the [Issues](https://github.com/yourusername/hardware-cwe-detection/issues) section
2. If not, create a new issue with a descriptive title and detailed description
3. Include steps to reproduce the issue, expected behavior, and actual behavior
4. Add relevant screenshots or code snippets if applicable

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature or bugfix: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Run tests to ensure your changes don't break existing functionality
5. Commit your changes with clear, descriptive commit messages
6. Push to your fork and submit a pull request to the main repository
7. Describe your changes in the pull request description

### Code Style

- Follow PEP 8 style guidelines for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Include docstrings for functions and classes

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/hardware-cwe-detection.git
   cd hardware-cwe-detection
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install development dependencies:
   ```bash
   pip install pytest flake8 black
   ```

## Adding New Features

### Adding Support for New Models

To add support for a new LLM:

1. Update the `MODELS` list in `scripts/baseline_framework.py`
2. Create a new query function for the model
3. Add a prompt template in the `PROMPT_TEMPLATES` dictionary
4. Update the `run_baseline_tests.py` script to handle the new model

### Adding New CWE Types

To add support for new CWE vulnerability types:

1. Update the CWE list CSV file with the new CWE information
2. Create example RTL files with the new vulnerability type
3. Update the synthetic dataset generation script if needed

## Testing

Run tests before submitting a pull request:

```bash
pytest
```

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
