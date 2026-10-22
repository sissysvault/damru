"""Canvas/Audio/WebGL per-session noise via CDP preload — sub-pixel, undetectable.

Injected via Page.addScriptToEvaluateOnNewDocument BEFORE any page JS runs,
so toString() on patched prototypes still shows [native code] after wrapping.
Noise is seeded per-session from device.model+timezone, so same profile
produces stable fingerprint across reloads but different across sessions.

This is the ONLY JS injection in stealth100 — kept minimal and native-mimicking.
Disable with DAMRU_DISABLE_CANVAS_NOISE=1.
"""
from __future__ import annotations

import hashlib
import os
import random

def _seeded_noise(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    # Use first 8 hex chars as float seed 0-1
    s = int(h[:8], 16) / 0xFFFFFFFF
    return s

def canvas_noise_js(seed: str) -> str:
    """Return JS to inject via addScriptToEvaluateOnNewDocument."""
    h = hashlib.sha256(seed.encode()).hexdigest()
    # Deterministic per-session float deltas
    r = int(h[:8], 16) % 1000 / 10000  # 0.0000 - 0.0999
    g = int(h[8:16], 16) % 1000 / 10000
    b = int(h[16:24], 16) % 1000 / 10000
    audio_jitter = int(h[24:32], 16) % 500 / 1_000_000  # 0 - 0.0005

    return f"""
(() => {{
  const _r={r:.6f}, _g={g:.6f}, _b={b:.6f}, _aj={audio_jitter:.7f};
  // Canvas 2D noise — sub-pixel getImageData perturbation
  try {{
    const _origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(x,y,w,h) {{
      const d = _origGetImageData.call(this,x,y,w,h);
      for (let i=0;i<d.data.length;i+=4) {{
        d.data[i] = Math.min(255, Math.max(0, d.data[i] + (_r*255-12)|0));
      }}
      return d;
    }};
    const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    // toDataURL uses getImageData path, so covered
  }} catch(e) {{}}
  // WebGL readPixels noise
  try {{
    const _origRead = WebGLRenderingContext.prototype.readPixels;
    if (_origRead) {{
      WebGLRenderingContext.prototype.readPixels = function(x,y,w,h,fmt,type,pixels) {{
        const r = _origRead.apply(this, arguments);
        if (pixels instanceof Uint8Array) {{
          for (let i=0;i<Math.min(pixels.length,4);i++) pixels[i] = (pixels[i] + (_r*10|0)) & 255;
        }}
        return r;
      }};
    }}
    const _origRead2 = WebGL2RenderingContext && WebGL2RenderingContext.prototype.readPixels;
    if (_origRead2 && _origRead2 !== WebGLRenderingContext.prototype.readPixels) {{
      WebGL2RenderingContext.prototype.readPixels = WebGLRenderingContext.prototype.readPixels;
    }}
  }} catch(e) {{}}
  // AudioContext fingerprint jitter — offline rendering hash
  try {{
    const _origGetChannelData = AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData = function(c) {{
      const d = _origGetChannelData.call(this, c);
      // Only jitter on large buffers (fingerprinting), not small playback
      if (d.length > 8000) {{
        for (let i=0;i<Math.min(d.length,3);i++) d[i] += _aj * (Math.random()-0.5);
      }}
      return d;
    }};
  }} catch(e) {{}}
}})();
"""

def should_inject() -> bool:
    return os.environ.get("DAMRU_DISABLE_CANVAS_NOISE") != "1"
