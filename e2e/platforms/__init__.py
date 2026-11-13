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
    audience: str | None = None  # OIDC token audience, if not the job's default

    def inputs(self) -> dict[str, str]:
        """Inputs for the CI run, as defined by the reference CI configs."""
        inputs = {
            "pia_url": self.pia_url,
            "product_name": self.product_name,
            "product_version": self.product_version,
            "bom": self.bom_b64,
        }
        if self.audience:
            inputs["audience"] = self.audience
        return inputs


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
