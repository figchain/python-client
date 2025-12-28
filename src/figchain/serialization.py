import io
import json
import dataclasses
import uuid
import datetime
import os
from enum import Enum
from typing import Type, TypeVar, Any, Dict, List, Set, get_type_hints, Union, Optional
import avro.schema
import avro.io
import avro.datafile
from . import models

T = TypeVar("T")

class _NonClosingBytesIO(io.BytesIO):
    def close(self):
        pass
    def actual_close(self):
        super().close()

# Global Names object to track all schemas
_NAMES = avro.schema.Names()

# Load bundled schema
_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.avsc")
if os.path.exists(_SCHEMA_PATH):
    with open(_SCHEMA_PATH, "r") as f:
        # Parsing into _NAMES allows looking up types by name later
        avro.schema.make_avsc_object(json.load(f), _NAMES)

def register_schema(schema_json: Any):
    # This allows adding new schemas (like UserConfig in tests) to the global registry
    avro.schema.make_avsc_object(schema_json, _NAMES)

def register_schema_from_file(path: str):
    with open(path, "r") as f:
        register_schema(json.load(f))

def get_schema(name: str) -> avro.schema.Schema:
    if isinstance(name, str) and (name.startswith('{') or name.startswith('"')):
        return avro.schema.parse(name)

    # Try full name and short name
    full_name = f"io.figchain.avro.model.{name}"
    schema = _NAMES.get_name(full_name, None)
    if not schema:
        schema = _NAMES.get_name(name, None)

    if not schema:
        # Fallback for patterns that might not match exactly
        for k, v in _NAMES.names.items():
            if k.endswith(f".{name}"):
                return v

    if not schema:
        raise ValueError(f"Schema {name} not found")

    return schema

def _to_avro_friendly(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        # We manually iterate to avoid issues with asdict recursion if we want to override types
        data = {}
        for f in dataclasses.fields(obj):
            data[f.name] = _to_avro_friendly(getattr(obj, f.name))
        return data
    elif isinstance(obj, uuid.UUID):
        return str(obj)
    elif isinstance(obj, datetime.datetime):
        # We need to return datetime objects for modern avro library to handle logical types
        # But we must ensure they are UTC and naive/aware as per library expectation.
        # Avro library usually expects aware datetime for timestamp-millis.
        if obj.tzinfo is None:
            return obj.replace(tzinfo=datetime.timezone.utc)
        return obj
    elif isinstance(obj, list):
        return [_to_avro_friendly(x) for x in obj]
    elif isinstance(obj, set):
        return [_to_avro_friendly(x) for x in obj]
    elif isinstance(obj, dict):
        return {k: _to_avro_friendly(v) for k, v in obj.items()}
    elif isinstance(obj, models.Operator):
        return obj.value
    return obj

def _from_avro_friendly(data: Any, cls: Type[T]) -> T:
    if data is None:
        return None

    origin = getattr(cls, "__origin__", None)
    if origin is Union:
        args = cls.__args__
        non_none_args = [a for a in args if a is not type(None)]
        if len(non_none_args) == 1:
            return _from_avro_friendly(data, non_none_args[0])
        return data

    if cls is Any or cls is dict or cls is Dict:
        return data

    if dataclasses.is_dataclass(cls):
        hints = get_type_hints(cls)
        kwargs = {}
        for field in dataclasses.fields(cls):
            val = data.get(field.name)
            if val is not None:
                kwargs[field.name] = _from_avro_friendly(val, hints[field.name])
        return cls(**kwargs)

    if cls is uuid.UUID and isinstance(data, str):
        return uuid.UUID(data)

    if cls is datetime.datetime and isinstance(data, (int, float)):
        return datetime.datetime.fromtimestamp(data / 1000.0, tz=datetime.timezone.utc)

    if origin is list or origin is List:
        item_type = cls.__args__[0]
        return [_from_avro_friendly(x, item_type) for x in data]

    if origin is set or origin is Set:
        item_type = cls.__args__[0]
        return set(_from_avro_friendly(x, item_type) for x in data)

    if isinstance(cls, type) and issubclass(cls, Enum):
        return cls(data)

    return data

def serialize(obj: Any, schema_name: str) -> bytes:
    """Serializes an object to raw Avro binary."""
    schema = get_schema(schema_name)
    writer = avro.io.DatumWriter(schema)
    bytes_writer = io.BytesIO()
    encoder = avro.io.BinaryEncoder(bytes_writer)
    writer.write(_to_avro_friendly(obj), encoder)
    return bytes_writer.getvalue()

def deserialize(data: bytes, schema_name: str, cls: Type[T]) -> T:
    """Deserializes an object from raw Avro binary."""
    schema = get_schema(schema_name)
    reader = avro.io.DatumReader(schema)
    bytes_reader = io.BytesIO(data)
    decoder = avro.io.BinaryDecoder(bytes_reader)
    datum = reader.read(decoder)
    return _from_avro_friendly(datum, cls)

def serialize_ocf(obj: Any, schema_name: str) -> bytes:
    """Serializes an object to Avro Object Container File (OCF) format."""
    schema = get_schema(schema_name)
    writer = avro.io.DatumWriter(schema)
    bytes_writer = _NonClosingBytesIO()
    with avro.datafile.DataFileWriter(bytes_writer, writer, schema) as dfw:
        dfw.append(_to_avro_friendly(obj))
    res = bytes_writer.getvalue()
    bytes_writer.actual_close()
    return res

def deserialize_ocf(data: bytes, schema_name: str, cls: Type[T]) -> T:
    """Deserializes an object from Avro Object Container File (OCF) format."""
    bytes_reader = _NonClosingBytesIO(data)
    with avro.datafile.DataFileReader(bytes_reader, avro.io.DatumReader()) as dfr:
        for datum in dfr:
            res = _from_avro_friendly(datum, cls)
            # We must break here to avoid DataFileReader reading more from (potentially closed) stream
            break
    bytes_reader.actual_close()
    return res
