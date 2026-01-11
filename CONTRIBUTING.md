# Contributing to FigChain Python Client

Thank you for your interest in contributing!

## Development Setup

1. **Clone the repository:**
    ```bash
    git clone https://github.com/figchain/python-client.git
    cd python-client
    ```

2. **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install dependencies (including dev tools):**
    ```bash
    pip install -e .[dev]
    ```

4. **Run tests:**
    ```bash
    pytest
    ```

## Tips
- All development dependencies (testing, linting, formatting) are included in the `[dev]` extra.
- The code uses a `src/` layout. Installing with `-e .` ensures imports work correctly.
- Please ensure all tests pass before submitting a pull request.

## Need Help?
If you have any questions, open an issue or ask in the discussions!
