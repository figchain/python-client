import io
import json
import dataclasses
import uuid
import datetime
import os
from typing import Type, TypeVar, Any, Dict, List, get_type_hints, Union
import avro.schema
import avro.io
from . import models

T = TypeVar("T")

# Load schema
_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.avsc")
if not os.path.exists(_SCHEMA_PATH):
    raise FileNotFoundError(f"Schema file not found at {_SCHEMA_PATH}")

with open(_SCHEMA_PATH, "r") as f:
    _SCHEMA_JSON = json.load(f)

_NAMES = avro.schema.Names()
for s in _SCHEMA_JSON:
    avro.schema.make_avsc_object(s, _NAMES)

def register_schema(schema_json: Any):
    if isinstance(schema_json, list):
         for s in schema_json:
             avro.schema.make_avsc_object(s, _NAMES)
    else:
         avro.schema.make_avsc_object(schema_json, _NAMES)

def register_schema_from_file(path: str):
    with open(path, "r") as f:
        register_schema(json.load(f))

def get_schema(name: str) -> avro.schema.Schema:
    # Try full name first
    full_name = f"io.figchain.avro.model.{name}"
    schema = _NAMES.get_name(full_name, None)
    if schema: 
        return schema
        
    # Try raw name
    schema = _NAMES.get_name(name, None)
    if schema:
        return schema

    # Try searching by simple name in all names?
    # _NAMES.names is a dict of full_name -> schema
    for k, v in _NAMES.names.items():
        if k.endswith(f".{name}"):
            return v
            
    raise ValueError(f"Schema {name} not found")

def _to_avro_friendly(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return {k: _to_avro_friendly(v) for k, v in dataclasses.asdict(obj).items()}
    elif isinstance(obj, uuid.UUID):
        return str(obj)
    elif isinstance(obj, datetime.datetime):
        if obj.tzinfo is None:
            return obj.replace(tzinfo=datetime.timezone.utc)
        return obj
    elif isinstance(obj, list):
        return [_to_avro_friendly(x) for x in obj]
    elif isinstance(obj, dict):
        return {k: _to_avro_friendly(v) for k, v in obj.items()}
    elif isinstance(obj, models.Operator):
        return obj.value
    return obj

def serialize(obj: Any, schema_name: str) -> bytes:
    schema = get_schema(schema_name)
    writer = avro.io.DatumWriter(schema)
    bytes_writer = io.BytesIO()
    encoder = avro.io.BinaryEncoder(bytes_writer)
    data = _to_avro_friendly(obj)
    writer.write(data, encoder)
    return bytes_writer.getvalue()

def _from_avro_friendly(data: Any, cls: Type[T]) -> T:
    if data is None:
        return None
        
    # Handle generic types like List, Dict, Optional
    origin = getattr(cls, "__origin__", None)
    if origin is list:
        item_type = cls.__args__[0]
        return [_from_avro_friendly(x, item_type) for x in data] # type: ignore
    elif origin is dict:
        val_type = cls.__args__[1]
        return {k: _from_avro_friendly(v, val_type) for k, v in data.items()} # type: ignore
    elif origin is Union: # Optional[T] is Union[T, None]
         args = cls.__args__
         non_none = [a for a in args if a is not type(None)]
         if len(non_none) == 1:
             return _from_avro_friendly(data, non_none[0])
         return data

    try:
        if cls is uuid.UUID:
            if isinstance(data, uuid.UUID):
                return data
            return uuid.UUID(data)
        elif cls is datetime.datetime:
            if isinstance(data, datetime.datetime):
                return data
            return datetime.datetime.fromtimestamp(data / 1000.0)
        elif isinstance(cls, type) and issubclass(cls, models.Operator):
            return cls(data)
        elif dataclasses.is_dataclass(cls):
            # Resolve types
            type_hints = get_type_hints(cls)
            kwargs = {}
            for k, v in data.items():
                if k in type_hints:
                    kwargs[k] = _from_avro_friendly(v, type_hints[k])
            return cls(**kwargs)
    except TypeError:
        # Fallback for simple types or if issubclass fails
        pass
        
    return data

def deserialize(data: bytes, schema_name: str, cls: Type[T]) -> T:
    schema = get_schema(schema_name)
    reader = avro.io.DatumReader(schema)
    bytes_reader = io.BytesIO(data)
    decoder = avro.io.BinaryDecoder(bytes_reader)
    dict_data = reader.read(decoder)
    return _from_avro_friendly(dict_data, cls)
