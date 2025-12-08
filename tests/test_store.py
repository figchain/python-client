
import pytest
import uuid
from figchain.store import Store
from figchain.models import FigFamily, FigDefinition

def test_store_ops():
    store = Store()
    
    # Empty get
    assert store.get_fig_family("ns", "key") is None
    
    # Put
    fam = FigFamily(
        definition=FigDefinition(namespace="ns", key="key", figId=uuid.uuid4(), schemaUri="s", schemaVersion="1", createdAt=None, updatedAt=None),
        figs=[],
        rules=[],
        defaultVersion=None
    )
    store.put(fam)
    
    # Get
    retrieved = store.get_fig_family("ns", "key")
    assert retrieved == fam
    
    # Put another namespace
    fam2 = FigFamily(
        definition=FigDefinition(namespace="ns2", key="key", figId=uuid.uuid4(), schemaUri="s", schemaVersion="1", createdAt=None, updatedAt=None),
        figs=[],
        rules=[],
        defaultVersion=None
    )
    store.put(fam2)
    assert store.get_fig_family("ns2", "key") == fam2
    
    # Clear
    store.clear()
    assert store.get_fig_family("ns", "key") is None
    assert store.get_fig_family("ns2", "key") is None

def test_put_all():
    store = Store()
    f1 = FigFamily(
        definition=FigDefinition(namespace="ns", key="k1", figId=uuid.uuid4(), schemaUri="s", schemaVersion="1", createdAt=None, updatedAt=None),
        figs=[], rules=[], defaultVersion=None
    )
    f2 = FigFamily(
        definition=FigDefinition(namespace="ns", key="k2", figId=uuid.uuid4(), schemaUri="s", schemaVersion="1", createdAt=None, updatedAt=None),
        figs=[], rules=[], defaultVersion=None
    )
    store.put_all([f1, f2])
    
    assert store.get_fig_family("ns", "k1") == f1
    assert store.get_fig_family("ns", "k2") == f2
