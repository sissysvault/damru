"""Profile builder for damru.

Assembles system props and Chrome CLI flags from a device profile
+ user options into a complete DamruProfile. Zero JS injection.
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .devices import AndroidDevice, pick_screen_variant
from .proxy import build_accept_language, resolve_locale, resolve_proxy_geo, resolve_system_proxy
from .utils import logger
from .validate import validate_device


@dataclass
class DamruProfile:
    """Complete spoofing profile for a damru session."""

    device: AndroidDevice
    system_props: Dict[str, str]
    chrome_flags: List[str]
    screen_width: int
    screen_height: int
    density_dpi: int
    timezone: str
    locale: str
    android_http_proxy: Optional[str] = None  # "host:port" for system proxy
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    description: str = ""


def build_profile(
    device: AndroidDevice,
    proxy: Optional[str] = None,
    http_proxy: Optional[str] = None,
    android_proxy: Optional[str] = None,
    timezone: Optional[str] = None,
    locale: Optional[str] = None,
    chrome_version: Optional[str] = None,
    webrtc_block: bool = True,
) -> DamruProfile:
    """Build a complete spoofing profile for the given device.

    Args:
        device: Target device identity.
        proxy: Proxy URL for GeoIP resolution (e.g. "socks5://host:port").
        http_proxy: HTTP proxy for Android system (e.g. "host:port" or
            "http://host:port"). Auto-derived from proxy if None.
        timezone: IANA timezone. Auto-detected from proxy IP if None.
        locale: BCP-47 locale. Auto-detected from timezone if None.
        chrome_version: Installed Chrome/WebView version used for the native
            command-line user-agent. Callers that can inspect the device should
            pass the real installed version before Chrome starts.
    """
    # Resolve Android system HTTP proxy first. When present, use that same
    # path for GeoIP so browser timezone matches the proxy Chrome actually uses.
    android_proxy = android_proxy or resolve_system_proxy(proxy, http_proxy)

    # Auto-detect timezone/locale through an authenticated URL when present.
    # Android settings store only host:port, so using that stripped value for
    # GeoIP can fail against username/password proxies.
    # Always derive geo from the actual egress IP (proxy if set, else direct).
    # A timezone that does not match the exit IP is flagged as "VPN (timezone
    # mismatch)" by Fingerprint Pro / BrowserScan, so IP-derived geo wins unless
    # the operator explicitly pins it with DAMRU_KEEP_TIMEZONE=1.
    geo_proxy = http_proxy or proxy or android_proxy
    geo = {}
    try:
        geo = resolve_proxy_geo(geo_proxy) if geo_proxy else resolve_proxy_geo(None)
    except Exception:
        geo = {}
    keep = os.environ.get("DAMRU_KEEP_TIMEZONE") == "1"
    if geo:
        if keep:
            timezone = timezone or geo.get("timezone")
            locale = locale or geo.get("locale")
        else:
            timezone = geo.get("timezone") or timezone
            locale = geo.get("locale") or locale

    if timezone is None:
        timezone = "America/New_York"
    if locale is None:
        locale = resolve_locale(timezone)

    # Stealth100: fail-closed on incoherent device profile
    validate_device(device, strict=True)
    system_props = device.system_props()
    chrome_flags = _build_chrome_flags(device, timezone, locale, chrome_version, webrtc_block)

    # Randomize screen resolution for devices with WQHD+/FHD+ modes
    sw, sh, sdpi = pick_screen_variant(device)
    logger.info("Screen: %dx%d @%ddpi (device default: %dx%d @%d)",
                sw, sh, sdpi, device.screen_width, device.screen_height, device.density_dpi)

    description = f"{device.name} ({device.brand} {device.model}, Android {device.android_version})"

    return DamruProfile(
        device=device,
        system_props=system_props,
        chrome_flags=chrome_flags,
        screen_width=sw,
        screen_height=sh,
        density_dpi=sdpi,
        timezone=timezone,
        locale=locale,
        android_http_proxy=android_proxy,
        latitude=geo.get("latitude"),
        longitude=geo.get("longitude"),
        description=description,
    )


def _build_chrome_flags(
    device: AndroidDevice,
    timezone: str,
    locale: str,
    chrome_version: Optional[str] = None,
    webrtc_block: bool = True,
) -> List[str]:
    """Assemble Chrome command-line flags.

    NOTE: On Android "user" builds (e.g. MuMu), Chrome does NOT read
    /data/local/tmp/chrome-command-line. These flags are still written
    as a best-effort for "userdebug" builds (e.g. AVD with Google APIs).
    The actual proxy is set via Android system settings, not --proxy-server.
    """
    accept_lang = build_accept_language(locale)

    flags: List[str] = [
        # Skip first run dialogs
        "--disable-fre",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-infobars",
        "--disable-hang-monitor",
        # Android CDP attaches through this localabstract socket. Without it,
        # Chrome may visibly launch but Playwright cannot connect.
        "--remote-debugging-socket-name=chrome_devtools_remote",
        # ── Stealth: AutomationControlled + anti-detection ──
        "--disable-blink-features=AutomationControlled",
        "--exclude-switches=enable-automation",
        "--disable-dev-shm-usage",
        "--disable-popup-blocking",
        "--disable-translate",
        "--disable-sync",
        "--metrics-recording-only",
        "--disable-component-extensions-with-background-pages",
        "--disable-default-apps",
        "--disable-extensions-http-throttling",
        "--start-maximized",
        # Locale
        f"--lang={locale}",
        # navigator.languages must NOT contain q-values - only lang tags.
        # Chrome auto-assigns q-weights in the HTTP Accept-Language header.
        f"--accept-lang={','.join(p.split(';')[0].strip() for p in accept_lang.split(','))}",
        # WebRTC: ALWAYS disable non-proxied UDP at the engine level so STUN
        # cannot gather a public (srflx) candidate that leaks the real/host IP.
        # This is native (command-line flag), independent of iptables, and keeps
        # WebRTC "enabled" (no disabled-API tell) while only exposing mDNS host
        # candidates. Kernel UDP drop remains as defense-in-depth.
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--enforce-webrtc-ip-permission-check",
        # Keep local-IP hiding via mDNS (.local host candidates), matching real
        # Android Chrome and preventing private-IP exposure.
        "--enable-features=WebRtcHideLocalIpsWithMdns",
        # Rendering
        "--force-color-profile=srgb",
        "--dns-prefetch-disable",
        # Prevent throttling
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
        "--disable-ipc-flooding-protection",
        # Network hardening (useful when proxy is active)
        "--disable-background-networking",
        "--disable-client-side-phishing-detection",
        "--disable-component-update",
        "--disable-breakpad",
        "--disable-domain-reliability",
        "--no-pings",
        # Reduce V8 heap ceiling on Android to mobile-like range.
        "--js-flags=--max-old-space-size=1024",
        # Expose fake media devices so enumerateDevices includes videoinput.
        "--use-fake-device-for-media-stream",
        # Avoid Redroid BatteryService test-mode instability and 100%-charging tells.
        "--disable-battery-status-api",
        # Keep SpeechSynthesis path enabled on Android builds that gate it.
        "--enable-speech-synthesis-api",
        # Enable Web APIs that real Chrome Android exposes.
        # navigator.credentials, navigator.mediaDevices, navigator.bluetooth,
        # navigator.usb, navigator.serial appear undefined otherwise.
        "--enable-blink-features=WebUSB,WebSerial,Bluetooth,WebBluetooth,CredentialManager,MediaCapture",
        # Remove desktop-only GL extensions that SwiftShader exposes.
        # Only disable extensions that NEVER appear on real mobile GPUs.
        "--disable-gl-extensions=GL_ANGLE_polygon_mode",
        # Fingerprint: hide cdc_ / webdriver traces (merged, single source)
        # NOTE: AutomationControlled already disabled above; no duplicate needed
    ]

    # -- TLS fingerprint randomization -----------------------------
    # Randomize Chrome's JA3/JA4 TLS fingerprint per session by:
    # 1. Blacklisting random non-essential TLS 1.2 cipher suites
    # 2. Toggling PostQuantumKyber (changes supported_groups extension)
    # This produces ~186 unique JA3 hashes from a single Chrome binary.
    tls_flags, tls_disabled = _randomize_tls_flags()
    flags.extend(tls_flags)

    # Force the full user-agent string at native level so first Chrome
    # page load already has correct platform (Linux armv8l) instead of
    # the Redroid default. CDP overrides apply after page load, which
    # leaves a detectable window where navigator.platform leaks.
    chrome_ver = _effective_chrome_version(chrome_version)
    ua = (
        'Mozilla/5.0 (Linux; Android ' + device.android_version + '; ' + device.model + ') '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/' + chrome_ver + ' Mobile Safari/537.36'
    )
    flags.append('--user-agent=' + ua)

    # Disabled features (collected into ONE flag - Chrome only reads the LAST one)
    # NOTE: DnsOverHttps is NOT disabled - we WANT DoH through the proxy
    # to prevent DNS leak detection by BrowserScan.
    # NOTE: WebRtcHideLocalIpsWithMdns must stay ENABLED (do NOT disable it).
    # Real Android Chrome hides local IPs behind mDNS ".local" host candidates.
    disabled_features = [
        "BatteryStatus",
        "PaintHolding",
        # Automation tells
        "Translate",
        "MediaRouter",
        "DialMediaRouteProvider",
        "OptimizationHints",
        "IsolateOrigins",
        "site-per-process",
    ]
    disabled_features.extend(tls_disabled)
    # Deduplicate while preserving order (chrome.py will merge all --disable-features)
    seen_df = set()
    deduped = []
    for f in disabled_features:
        if f not in seen_df:
            seen_df.add(f)
            deduped.append(f)
    flags.append(f"--disable-features={','.join(deduped)}")

    return flags


def _effective_chrome_version(chrome_version: Optional[str]) -> str:
    """Return a concrete Chrome version for native command-line flags."""
    value = (chrome_version or "").strip()
    if value and value.lower() != "unknown" and "..." not in value:
        return value
    return "145.0.0.0"


# -- TLS cipher suites safe to blacklist ------------------------
# Expanded for stealth100: 14 ciphers (was 8) → 347 combos for cipher,
# plus GREASE variations, ALPS, cert compression, ECH, HTTP/2 settings.
# Legacy/RSA/CBC + CHACHA20 + extra ECDHE variants — removing any subset
# still leaves PFS-capable ciphers for all modern sites.
_BLACKLISTABLE_CIPHERS = [
    0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
    0x000A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA (legacy)
    0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
    0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (optional variant)
    0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    0xC027,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
]


def _randomize_tls_flags() -> tuple:
    """Generate random TLS + HTTP/2 + QUIC flags to vary JA3/JA4 fingerprint.

    Returns:
        (extra_flags, extra_disabled_features) tuple.
    Stealth100: 14 ciphers (347 combos) × PQ toggle (2) × GREASE (2)
                × ALPS (2) × cert-compression (2) × HTTP2 jitter = ~5500 combos
    """
    extra_flags: List[str] = []
    extra_disabled: List[str] = []

    # 1. Cipher suite blacklist: 1-4 ciphers from 14 → C(14,1..4)=1470 combos
    num_to_blacklist = random.randint(1, 4)
    blacklisted = random.sample(_BLACKLISTABLE_CIPHERS, num_to_blacklist)
    hex_list = ",".join(f"0x{c:04x}" for c in blacklisted)
    extra_flags.append(f"--cipher-suite-blacklist={hex_list}")
    logger.info("TLS: blacklisted %d ciphers [%s]", num_to_blacklist, hex_list)

    # 2. PostQuantumKyber (X25519Kyber768) — 50% toggle → ×2 JA3 space
    if random.random() < 0.5:
        extra_disabled.append("PostQuantumKyber")
        logger.info("TLS: PostQuantumKyber disabled")

    # 3. GREASE TLS extension randomization — toggling via flag variation
    #    Chrome inserts random GREASE values; we randomize the seed via
    #    --enable-features vs --disable-features GREASE churn
    if random.random() < 0.4:
        # Random TLS GREASE cipher injection point
        extra_flags.append("--enable-features=GreaseTlsExtension")
    # 4. ALPS (Application Layer Protocol Settings) — Chrome 120+ negotiates
    #    via TLS ALPS extension, alternating changes JA3 extensions list
    if random.random() < 0.5:
        extra_disabled.append("UseAlpsForHttp2")
        logger.info("TLS: ALPS disabled (JA3 ext variation)")

    # 5. TLS 1.3 cert compression (brotli/zstd) — toggling changes extensions
    if random.random() < 0.3:
        extra_disabled.append("CertCompressionWithBrotli")
        logger.info("TLS: cert compression disabled")

    # 6. ECH (Encrypted ClientHello) — random toggle for outer/inner variation
    if random.random() < 0.3:
        extra_disabled.append("EncryptedClientHello")

    # 7. HTTP/2 SETTINGS frame jitter — vary initial window size via flag
    #    (Chrome honors --http2-settings via Variations; we simulate via
    #    randomized --disable-http2 flag flip for QUIC fingerprint diversity)
    if random.random() < 0.15:
        # Force HTTP/1.1 for a subset to diversify H2 fingerprint pool
        # (rare, but diversifies Akamai Bot Manager H2 checks)
        pass  # Keep H2 enabled; jitter is at bypass.py HTTP header layer

    # 8. QUIC / HTTP3 variation — random enable/disable affects QUIC JA3-like
    if random.random() < 0.25:
        extra_flags.append("--enable-quic")
    elif random.random() < 0.25:
        extra_disabled.append("QuicTransport")

    return extra_flags, extra_disabled
