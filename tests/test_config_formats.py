import json
import yaml
import importlib.util
from pathlib import Path

# Load Config module directly to avoid importing the whole package (tests run without deps)
spec = importlib.util.spec_from_file_location("figchain.config", str(Path(__file__).parents[1] / "src" / "figchain" / "config.py"))
config_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config_mod)
Config = config_mod.Config


def test_load_yaml_and_json(tmp_path):
    data = {
        "base_url": "https://example.org/api/",
        "environment_id": "env-123",
        "namespaces": ["ns1", "ns2"],
        "poll_interval": 30,
    }

    # YAML file
    yaml_file = tmp_path / "cfg.yaml"
    yaml_file.write_text(yaml.dump(data))

    cfg = Config.load(path=str(yaml_file))
    assert cfg.base_url == "https://example.org/api/"
    assert cfg.environment_id == "env-123"
    assert set(cfg.namespaces) == {"ns1", "ns2"}

    # JSON file
    json_file = tmp_path / "cfg.json"
    json_file.write_text(json.dumps(data))

    cfg2 = Config.load(path=str(json_file))
    assert cfg2.base_url == "https://example.org/api/"
    assert cfg2.environment_id == "env-123"
    assert set(cfg2.namespaces) == {"ns1", "ns2"}


def test_load_no_ext_try_yaml_then_json(tmp_path):
    data = {
        "base_url": "https://fallback.example/",
        "environment_id": "env-xyz",
        "namespaces": ["a"],
    }

    # write YAML to a file without extension
    f = tmp_path / "cfg"
    f.write_text(yaml.dump(data))

    cfg = Config.load(path=str(f))
    assert cfg.base_url == "https://fallback.example/"
    assert cfg.environment_id == "env-xyz"
    assert set(cfg.namespaces) == {"a"}

    # overwrite with JSON and ensure it still works
    f.write_text(json.dumps(data))
    cfg2 = Config.load(path=str(f))
    assert cfg2.base_url == "https://fallback.example/"
    assert cfg2.environment_id == "env-xyz"