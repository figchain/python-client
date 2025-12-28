# This file is generated. Do not edit.
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union, Any
from enum import Enum
import uuid
from datetime import datetime


class Operator(str, Enum):
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"
    CONTAINS = "CONTAINS"
    IN = "IN"
    NOT_IN = "NOT_IN"
    SPLIT = "SPLIT"

@dataclass(kw_only=True)
class Condition:
    variable: str
    operator: Operator
    values: List[str]

@dataclass(kw_only=True)
class Rule:
    description: Optional[str] = None
    conditions: List[Condition]
    targetVersion: uuid.UUID

@dataclass(kw_only=True)
class FigDefinition:
    namespace: str
    key: str
    figId: uuid.UUID
    schemaUri: str
    schemaVersion: str
    createdAt: datetime
    updatedAt: datetime

@dataclass(kw_only=True)
class Fig:
    figId: uuid.UUID
    version: uuid.UUID
    payload: bytes
    isEncrypted: bool = False
    wrappedDek: Optional[bytes] = None
    encryptionAlgorithm: Optional[str] = None
    keyId: Optional[str] = None

@dataclass(kw_only=True)
class FigFamily:
    definition: FigDefinition
    figs: List[Fig]
    rules: List[Rule] = field(default_factory=list)
    defaultVersion: Optional[uuid.UUID] = None

@dataclass(kw_only=True)
class InitialFetchRequest:
    namespace: str
    environmentId: uuid.UUID
    asOfTimestamp: Optional[datetime] = None

@dataclass(kw_only=True)
class InitialFetchResponse:
    figFamilies: List[FigFamily]
    cursor: str
    environmentId: uuid.UUID

@dataclass(kw_only=True)
class UpdateFetchRequest:
    namespace: str
    cursor: str
    environmentId: uuid.UUID

@dataclass(kw_only=True)
class UpdateFetchResponse:
    figFamilies: List[FigFamily]
    cursor: str
