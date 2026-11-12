"""CI platforms that run an SBOM upload against PIA.

A platform triggers a real (or, in the future, mocked) CI run that obtains an
OIDC token from its issuer and POSTs an SBOM to PIA. The run reports PIA's
response back, so tests judge success *and* expected failures the same way.
"""

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class UploadRequest:
    """What a CI run should upload, and where to."""

    pia_url: str
    product_name: str
    product_version: str
    bom_b64: str


@dataclass(frozen=True)
class UploadResult:
    """PIA's response as seen by the CI run."""

    status: int
    body: Any
    run_url: str


class Platform(Protocol):
    name: str
    workload_url: str  # as registered with `pia sync`
    product: str  # DependencyTrack product to upload to

    def run_upload(self, req: UploadRequest) -> UploadResult: ...
