"""Tests for the Prometheus metrics endpoint and definitions."""

import pytest
from prometheus_client import CONTENT_TYPE_PLAIN_0_0_4

import pia


@pytest.mark.usefixtures("setup_env")
class TestMetricsEndpoint:
    """Tests for the /metrics scrape endpoint."""

    def test_serves_prometheus_text_format(self, client):
        response = client.get("/metrics")

        assert response.status_code == 200
        assert response.headers["content-type"] == CONTENT_TYPE_PLAIN_0_0_4
        assert b"pia_http_requests_total" in response.content

    def test_reports_build_version(self, client, metric_value):
        """Info('pia_build') must expose `pia_build_info`, not `..._info_info`."""
        client.get("/metrics")

        assert metric_value("pia_build_info", version=pia.__version__) == 1.0
