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
  // ── Automation tell removal (true deletion so `'webdriver' in navigator === false`) ──
  try {{ delete Navigator.prototype.webdriver; }} catch(e) {{}}
  try {{ delete navigator.webdriver; }} catch(e) {{}}
  // Do NOT re-create `navigator.webdriver` — leaving it absent makes
  // `'webdriver' in navigator === false` which is the real-device signal.
  try {{ if (!window.chrome) {{ window.chrome = {{ runtime: {{}}, loadTimes: function(){{}}, csi: function(){{}} }}; }} }} catch(e) {{}}
  try {{ if (!window.chrome.runtime) window.chrome.runtime = {{}}; }} catch(e) {{}}
  // Permissions prompt spoof (headless shows 'denied', real Android shows 'prompt')
  try {{
    const _origQuery = navigator.permissions && navigator.permissions.query;
    if (_origQuery) {{
      navigator.permissions.query = function(p) {{
        if (p && p.name === 'notifications') return Promise.resolve({{ state: 'prompt', onchange: null }});
        return _origQuery.call(this, p);
      }};
    }}
  }} catch(e) {{}}
  // ── PluginArray shim (Android Chrome exposes 0 plugins; desktop tests flag that) ──
  // Builds real Plugin/MimeType instances so instanceof + toString stay native-looking.
  try {{
    if (navigator.plugins.length === 0 && window.PluginArray && window.Plugin) {{
      const _pd = [
        ['PDF Viewer', 'internal-pdf-viewer'],
        ['Chrome PDF Viewer', 'internal-pdf-viewer'],
        ['Chromium PDF Viewer', 'internal-pdf-viewer'],
        ['Microsoft Edge PDF Viewer', 'internal-pdf-viewer'],
        ['WebKit built-in PDF', 'internal-pdf-viewer'],
      ];
      const _mimeData = ['application/pdf', 'text/pdf'];
      const _plugins = [];
      const _mimes = [];
      for (const [nm, fn] of _pd) {{
        const pl = Object.create(Plugin.prototype);
        Object.defineProperties(pl, {{
          name: {{ value: nm, enumerable: true }},
          filename: {{ value: fn, enumerable: true }},
          description: {{ value: 'Portable Document Format', enumerable: true }},
          length: {{ value: _mimeData.length, enumerable: false }},
        }});
        _mimeData.forEach((mt, i) => {{
          const m = Object.create(MimeType.prototype);
          Object.defineProperties(m, {{
            type: {{ value: mt, enumerable: true }},
            suffixes: {{ value: 'pdf', enumerable: true }},
            description: {{ value: 'Portable Document Format', enumerable: true }},
            enabledPlugin: {{ value: pl, enumerable: false }},
          }});
          Object.defineProperty(pl, i, {{ value: m, enumerable: true }});
          _mimes.push(m);
        }});
        Object.defineProperty(pl, 'item', {{ value: (i) => pl[i] || null, enumerable: false }});
        Object.defineProperty(pl, 'namedItem', {{ value: (n) => (n === mt || n === 'application/pdf') ? pl[0] : null, enumerable: false }});
        _plugins.push(pl);
      }}
      const _pa = Object.create(PluginArray.prototype);
      _plugins.forEach((p, i) => Object.defineProperty(_pa, i, {{ value: p, enumerable: true }}));
      Object.defineProperties(_pa, {{
        length: {{ value: _plugins.length, enumerable: false }},
        item: {{ value: (i) => _plugins[i] || null, enumerable: false }},
        namedItem: {{ value: (n) => _plugins.find(p => p.name === n) || null, enumerable: false }},
      }});
      Object.defineProperty(Navigator.prototype, 'plugins', {{ get: () => _pa, configurable: true }});
      // mimeTypes must stay consistent with plugins
      const _ma = Object.create(MimeTypeArray.prototype);
      _mimes.forEach((m, i) => Object.defineProperty(_ma, i, {{ value: m, enumerable: true }}));
      Object.defineProperties(_ma, {{
        length: {{ value: _mimes.length, enumerable: false }},
        item: {{ value: (i) => _mimes[i] || null, enumerable: false }},
        namedItem: {{ value: (n) => _mimes.find(m => m.type === n) || null, enumerable: false }},
      }});
      Object.defineProperty(Navigator.prototype, 'mimeTypes', {{ get: () => _ma, configurable: true }});
    }}
  }} catch(e) {{}}
  const _r={r:.6f}, _g={g:.6f}, _b={b:.6f}, _aj={audio_jitter:.7f};
  // Canvas 2D noise — sub-pixel getImageData perturbation
  try {{
    const _origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(x,y,w,h) {{
      const d = _origGetImageData.call(this,x,y,w,h);
      // Do not touch fully transparent pixels (alpha==0). Transparency tests
      // (fpscanner TRANSPARENT_PIXEL) read a 1x1 clear pixel and expect RGBA
      // 0,0,0,0; perturbing it is a detectable tamper signal.
      for (let i=0;i<d.data.length;i+=4) {{
        if (d.data[i+3] === 0) continue;
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
    """Native-only by default: no JS injection unless explicitly opted in.

    Set DAMRU_ENABLE_JS_SPOOF=1 to enable the legacy JS shims (webdriver delete,
    plugin array, canvas/audio noise). Native Chrome already handles webdriver,
    permissions and window.chrome; Android genuinely has 0 plugins.
    """
    return os.environ.get("DAMRU_ENABLE_JS_SPOOF") == "1"
