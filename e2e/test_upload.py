from uuid import uuid4

import pytest

from .dependencytrack import DependencyTrack
from .platforms import Platform, UploadRequest
from .stack import Stack

PRODUCT = "gitlab-id-demo"
COMPONENT_PURL = "pkg:pypi/requests@2.32.3"  # see data/sbom.cdx.json


@pytest.mark.parametrize("platform", ["gitlab"], indirect=True)
def test_upload_success(
    platform: Platform, stack: Stack, dt: DependencyTrack, sbom_b64: str
) -> None:
    # Unique per run, so that a BOM from an earlier run can't pass the test
    version = f"e2e-{uuid4().hex[:8]}"

    result = platform.run_upload(
        UploadRequest(stack.public_url, PRODUCT, version, sbom_b64)
    )
    assert result.status == 200, result

    dt.wait_processed(result.body["polling_url"])
    project = dt.project(PRODUCT, version)
    assert project["parent"]["uuid"] == stack.product_uuid(PRODUCT)
    purls = {c.get("purl") for c in dt.components(project["uuid"])}
    assert COMPONENT_PURL in purls
