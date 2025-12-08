# FigChain Python Client

Official Python client library for [FigChain](https://figchain.io) configuration management.

## Features

- **Real-time configuration updates** - Subscribe to configuration changes with background polling
- **Rule-based rollouts** - Evaluate feature flags and configurations based on user context
- **Type-safe models** - Avro-based serialization for efficient data transfer with Python dataclasses
- **Flexible storage** - Thread-safe in-memory storage
- **Python 3.7+** - Support for modern Python versions

## Installation

Install using pip:

```bash
pip install figchain
```

## Quick Start

```python
from figchain import FigChainClient, Context

# Your generated config class (see "Generating Models")
from my_app.models import MyConfig 

# Initialize the client
client = FigChainClient(
    base_url="https://api.figchain.io",
    client_secret="your-client-secret",
    environment_id="your-environment-id",
    namespaces={"default"}
)

# Define context for evaluation (e.g., user properties for traffic splitting)
context: Context = {
    "userId": "user123",
    "plan": "premium"
}

# Fetch configuration safely
# returns Optional[MyConfig]
config = client.get_fig("your-fig-key", MyConfig, context=context)

if config:
    if config.enabled:
        print(f"Feature enabled with color: {config.backgroundColor}")
    else:
        print("Feature disabled")

# Clean up resources when done
client.close()
```

## Generating Models

The Python client uses Avro schemas to generate type-safe dataclasses. You can use the included script to generate these models from your `.avsc` files:

```bash
# If installed from source in venv:
python3 scripts/generate_models.py path/to/schema.avsc path/to/output_models.py
```

## Development

1. **Setup Environment**:
   ```bash
   python3 -m venv venv
   . venv/bin/activate
   pip install -e .[dev]
   ```

2. **Run Tests**:
   ```bash
   pytest
   ```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- [Documentation](https://docs.figchain.io)
- [Issues](https://github.com/figchain/python-client/issues)
- [Contact](mailto:support@figchain.io)
