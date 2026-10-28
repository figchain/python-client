# This file is generated. Do not edit.
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


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
    values: list[str]


@dataclass(kw_only=True)
class Rule:
    description: str | None = None
    conditions: list[Condition]
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
    wrappedDek: bytes | None = None
    encryptionAlgorithm: str | None = None
    keyId: str | None = None


@dataclass(kw_only=True)
class FigFamily:
    definition: FigDefinition
    figs: list[Fig]
    rules: list[Rule] = field(default_factory=list)
    defaultVersion: uuid.UUID | None = None


@dataclass(kw_only=True)
class InitialFetchRequest:
    namespace: str
    environmentId: uuid.UUID
    asOfTimestamp: datetime | None = None


@dataclass(kw_only=True)
class InitialFetchResponse:
    figFamilies: list[FigFamily]
    cursor: str
    environmentId: uuid.UUID
    schemas: dict[str, str] = field(default_factory=dict)


@dataclass(kw_only=True)
class UpdateFetchRequest:
    namespace: str
    cursor: str
    environmentId: uuid.UUID


@dataclass(kw_only=True)
class UpdateFetchResponse:
    figFamilies: list[FigFamily]
    cursor: str
    schemas: dict[str, str] = field(default_factory=dict)
