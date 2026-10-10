"""Public read-only camera discovery exports; implementation lives with HCNetSDK."""

from .hcnetsdk import HcNetSdkStreamDetails, discover_hcnetsdk_stream_details

__all__ = ["HcNetSdkStreamDetails", "discover_hcnetsdk_stream_details"]
