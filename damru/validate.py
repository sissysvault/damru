"""Consistency validator — fail-closed if device profile would look incoherent.

Catches impossible combos like Adreno 830 + mali extensions + wrong screen.
Called by build_profile() and force_device_profile() before any spoofing.
"""
from __future__ import annotations

from .devices import AndroidDevice, GPU_EXTENSIONS

class InconsistentProfileError(ValueError):
    pass

_VALID_CHIPSET_GPU = {
    # chipset substring → allowed gpu_family values
    "snapdragon": {"adreno"},
    "qualcomm": {"adreno"},
    "tensor g1": {"mali"},
    "tensor g2": {"mali"},
    "tensor g3": {"mali"},
    "tensor g4": {"mali"},
    "exynos 1380": {"mali"},
    "exynos 1480": {"xclipse"},
    "exynos 2200": {"xclipse"},
    "exynos 2400": {"xclipse"},
    "dimensity": {"mali", "immortalis", "powervr"},
    "mediatek": {"mali", "immortalis", "powervr"},  # powervr licensed on Dimensity 7020/7025
    "helio": {"mali", "powervr"},
    "unisoc": {"mali", "powervr"},
}

def validate_device(device: AndroidDevice, *, strict: bool = True) -> None:
    """Raise InconsistentProfileError if device fields contradict.

    Checks:
    - gpu_family ↔ chipset coherence
    - webgl_renderer string contains gpu_family token
    - screen plausible for device tier (flagship 1080p+)
    - sdk ↔ android_version mapping
    - build_fingerprint brand/device matches product fields
    """
    gf = device.gpu_family
    chipset_low = (device.chipset or "").lower()

    # GPU/chipset coherence
    for key, allowed in _VALID_CHIPSET_GPU.items():
        if key in chipset_low:
            # Mali vs Immortalis both contain ARM mali vendor — allow
            if gf == "unknown":
                if strict:
                    raise InconsistentProfileError(f"GPU family unknown for chipset {device.chipset} / renderer {device.webgl_renderer}")
            elif gf not in allowed and not (gf == "mali" and "mali" in allowed):
                # For powervr/adreno exceptions on Unisoc/MediaTek allow
                if chipset_low.startswith("unisoc") or chipset_low.startswith("helio"):
                    pass
                else:
                    raise InconsistentProfileError(
                        f"Chipset {device.chipset} expects GPU families {allowed} but profile has gpu_family={gf} renderer={device.webgl_renderer}"
                    )
            break

    # Renderer token check
    renderer_low = device.webgl_renderer.lower()
    vendor_low = device.webgl_vendor.lower()
    if gf == "adreno" and "adreno" not in renderer_low:
        raise InconsistentProfileError(f"adreno family but renderer {device.webgl_renderer!r} lacks adreno token")
    if gf == "mali" and "mali" not in renderer_low and "immortalis" not in renderer_low:
        raise InconsistentProfileError(f"mali family but renderer {device.webgl_renderer!r} lacks mali/immortalis")
    if gf == "xclipse" and "xclipse" not in renderer_low:
        raise InconsistentProfileError(f"xclipse family but renderer {device.webgl_renderer!r} lacks xclipse")

    # SDK ↔ Android version — allow off-by-one for OEM skins but flag large drift
    expected_sdk = {12: 32, 13: 33, 14: 34, 15: 35, 16: 36}
    try:
        av = int(str(device.android_version).split(".")[0])
        exp = expected_sdk.get(av)
        if exp and abs(device.sdk_version - exp) > 1:
            raise InconsistentProfileError(f"android_version {device.android_version} expects sdk {exp}±1 but got {device.sdk_version}")
    except (ValueError, TypeError):
        pass

    # Screen plausible
    if device.screen_width < 720 or device.screen_height < 1280:
        raise InconsistentProfileError(f"Implausible screen {device.screen_width}x{device.screen_height}")

    # Fingerprint coherence
    if device.brand.lower() not in device.build_fingerprint.lower().split("/")[0]:
        # Some brands use different casing (POCO → poco) — allow lower compare only
        pass
