from importlib.metadata import version

import pytest

import iplens
from iplens.cli import main


def test_version_comes_from_package_metadata(capsys):
    assert iplens.__version__ == version("aws-iplens")
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"iplens {iplens.__version__}"
