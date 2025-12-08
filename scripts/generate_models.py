import json
import os
from typing import Any, Dict, List, Optional, Union

AVRO_TYPE_MAPPING = {
    "string": "str",
    "boolean": "bool",
    "int": "int",
    "long": "int",
    "float": "float",
    "double": "float",
    "bytes": "bytes",
    "null": "None",
}

def resolve_type(type_def: Any, namespace: str) -> str:
    if isinstance(type_def, str):
        if type_def in AVRO_TYPE_MAPPING:
            return AVRO_TYPE_MAPPING[type_def]
        # Check if it's a fully qualified name or needs namespace
        if "." in type_def:
             return type_def.split(".")[-1]
        return type_def  # Assumed to be a class name in the same file

    if isinstance(type_def, list):
        # Union
        non_null_types = [t for t in type_def if t != "null"]
        if "null" in type_def and len(non_null_types) == 1:
            return f"Optional[{resolve_type(non_null_types[0], namespace)}]"
        return f"Union[{', '.join(resolve_type(t, namespace) for t in type_def)}]"

    if isinstance(type_def, dict):
        base_type = type_def.get("type")
        if base_type == "array":
            item_type = resolve_type(type_def.get("items"), namespace)
            return f"List[{item_type}]"
        elif base_type == "map":
            value_type = resolve_type(type_def.get("values"), namespace)
            return f"Dict[str, {value_type}]"
        
        logical_type = type_def.get("logicalType")
        if logical_type == "uuid":
            return "uuid.UUID"
        elif logical_type == "timestamp-millis":
            return "datetime"
        elif logical_type == "uri":
            return "str"
        
        # If it's a nested record definition (though usually defined at top level), handle it?
        # Assuming flattened definitions for now as per the schema list.
        if base_type in AVRO_TYPE_MAPPING:
            return AVRO_TYPE_MAPPING[base_type]
            
    return "Any"

def generate_code(schema_path: str, output_path: str):
    with open(schema_path, "r") as f:
        schemas = json.load(f)

    # Sort schemas? Or assume order of dependency...
    # Python forward references might be needed.
    # We will use string forward references for types if helpful, or just 'from __future__ import annotations'

    lines = [
        "# This file is generated. Do not edit.",
        "from __future__ import annotations",
        "from dataclasses import dataclass, field",
        "from typing import List, Dict, Optional, Union, Any",
        "from enum import Enum",
        "import uuid",
        "from datetime import datetime",
        "",
        "",
    ]

    for schema in schemas:
        type_name = schema["type"]
        name = schema["name"]
        namespace = schema.get("namespace", "")
        
        if type_name == "enum":
            lines.append(f"class {name}(str, Enum):")
            for symbol in schema["symbols"]:
                lines.append(f"    {symbol} = \"{symbol}\"")
            lines.append("")

        elif type_name == "record":
            lines.append("@dataclass(kw_only=True)")
            lines.append(f"class {name}:")
            fields = schema.get("fields", [])
            if not fields:
                lines.append("    pass")
            
            for field_def in fields:
                field_name = field_def["name"]
                field_type = resolve_type(field_def["type"], namespace)
                
                # Handle defaults
                default_val = field_def.get("default", ...)
                
                default_str = ""
                if default_val is not ...:
                    if default_val is None:
                        default_str = " = None"
                    elif isinstance(default_val, list) and len(default_val) == 0:
                         default_str = " = field(default_factory=list)"
                    elif isinstance(default_val, dict) and len(default_val) == 0:
                         default_str = " = field(default_factory=dict)"
                    elif isinstance(default_val, str):
                        default_str = f" = \"{default_val}\""
                    else:
                        default_str = f" = {default_val}"
                
                lines.append(f"    {field_name}: {field_type}{default_str}")
            lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    print(f"Generated {output_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: generate_models.py <schema_file> <output_file>")
        sys.exit(1)
    generate_code(sys.argv[1], sys.argv[2])
