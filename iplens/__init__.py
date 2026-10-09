"""IPLens: private IPv4 usage visibility & optimization across AWS accounts."""

from importlib.metadata import PackageNotFoundError, version

try:  # the version lives in pyproject.toml only
    __version__ = version("aws-iplens")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"
