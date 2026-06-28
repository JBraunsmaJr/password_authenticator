import pytest
from lib.vault import Vault

@pytest.fixture
def db_file(tmp_path):
    db = tmp_path / "test_vault.db"
    return str(db)

@pytest.fixture
def vault(db_file):
    with Vault(db_file) as v:
        yield v
