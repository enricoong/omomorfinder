"""
Visual brand-impersonation detection.

  * Perceptual hashes (DCT pHash + difference hash), implemented with numpy
    only, compare logos/favicons regardless of size, format or compression.
  * Shodan-compatible favicon MurmurHash3 and SHA-256 detect exact copies
    (phishing kits usually reuse the original favicon byte for byte).
  * Deep mode: ORB keypoint matching (OpenCV) finds a logo embedded in a
    bigger image, and Playwright screenshots compare whole pages.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import logging
from pathlib import Path

import numpy as np
from PIL import Image, ImageStat

from . import activity
from .config import TTL, Settings
from .models import ImageFingerprint, VisualMatch
from .net import HttpClient

log = logging.getLogger(__name__)

try:
    import mmh3  # Shodan favicon hash
except ImportError:  # pragma: no cover
    mmh3 = None

try:  # optional, deep mode
    import cv2  # type: ignore
except ImportError:  # pragma: no cover
    cv2 = None

Image.MAX_IMAGE_PIXELS = 40_000_000  # decompression-bomb guard

_DCT_N = 32
_DCT_MATRIX = np.array(
    [[np.cos(np.pi * (2 * n + 1) * k / (2 * _DCT_N)) for n in range(_DCT_N)] for k in range(_DCT_N)],
    dtype=np.float64,
)


def load_image(data: bytes) -> Image.Image | None:
    """
    Decode image bytes into an RGB Pillow image.

    ICO files use their largest frame; transparency is flattened on white so
    that transparent logos hash like they look on a web page.

    Args:
        data (bytes): Raw image bytes.
    Returns:
        Image.Image | None: RGB image, None when undecodable or too small.
    """
    try:
        img = Image.open(io.BytesIO(data))  # ICO: Pillow picks the largest frame
        img.load()
        if getattr(img, "n_frames", 1) > 1:
            img.seek(0)
        if img.mode in ("RGBA", "LA", "P"):
            img = img.convert("RGBA")
            bg = Image.new("RGBA", img.size, (255, 255, 255, 255))
            img = Image.alpha_composite(bg, img)
        img = img.convert("RGB")
    except Exception:  # Pillow raises many unrelated exception types
        return None
    if img.width < 8 or img.height < 8:
        return None
    return img


def is_flat(img: Image.Image) -> bool:
    """
    Whether an image is (almost) a single colour (spacer, placeholder).

    Args:
        img (Image.Image): RGB image.
    Returns:
        bool: True when the mean channel standard deviation is below 6.
    """
    stats = ImageStat.Stat(img.convert("L").resize((64, 64)))
    return stats.stddev[0] < 6


def dhash(img: Image.Image) -> int:
    """
    64-bit difference hash (gradient direction between neighbours).

    Args:
        img (Image.Image): Image.
    Returns:
        int: 64-bit hash.
    """
    px = np.asarray(img.convert("L").resize((9, 8), Image.Resampling.LANCZOS), dtype=np.int16)
    bits = (px[:, 1:] > px[:, :-1]).flatten()
    return int("".join("1" if b else "0" for b in bits), 2)


def phash(img: Image.Image) -> int:
    """
    64-bit DCT perceptual hash.

    Args:
        img (Image.Image): Image.
    Returns:
        int: 64-bit hash (low-frequency DCT coefficients vs. their median).
    """
    px = np.asarray(img.convert("L").resize((_DCT_N, _DCT_N), Image.Resampling.LANCZOS), dtype=np.float64)
    dct = _DCT_MATRIX @ px @ _DCT_MATRIX.T
    low = dct[:8, :8].flatten()
    med = np.median(low[1:])
    return int("".join("1" if v > med else "0" for v in low), 2)


def hash_similarity(a: ImageFingerprint, b: ImageFingerprint) -> float:
    """
    Similarity between two fingerprints from their hash Hamming distances.

    Args:
        a (ImageFingerprint): First fingerprint.
        b (ImageFingerprint): Second fingerprint.
    Returns:
        float: 1.0 identical ... ~0.5 unrelated (random hashes differ in
        about half of the bits).
    """
    if a.sha256 and a.sha256 == b.sha256:
        return 1.0
    dp = (a.phash ^ b.phash).bit_count()
    dd = (a.dhash ^ b.dhash).bit_count()
    return round(1 - (0.6 * dp + 0.4 * dd) / 64, 4)


def favicon_hash(data: bytes) -> int | None:
    """
    Shodan-compatible favicon hash (mmh3 of base64 with newlines).

    Usable directly in Shodan as `http.favicon.hash:<value>`.

    Args:
        data (bytes): Raw favicon bytes.
    Returns:
        int | None: Signed 32-bit hash, None if mmh3 is unavailable.
    """
    if mmh3 is None:
        return None
    return mmh3.hash(base64.encodebytes(data))


class VisualAnalyzer:
    """
    Downloads, fingerprints and compares brand images.

    Args (constructor):
        http (HttpClient): Shared HTTP client.
        settings (Settings): Size limits and deep-mode flag.
    """

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        """
        Store dependencies.

        Args:
            http (HttpClient): Shared HTTP client.
            settings (Settings): Scan configuration.
        Returns:
            None
        """
        self.http = http
        self.settings = settings
        self.raw: dict[str, bytes] = {}
        self.orb_available = cv2 is not None

    async def _download(self, url: str) -> bytes | None:
        """
        Download image bytes (data: URIs are decoded locally).

        Args:
            url (str): Image URL or data URI.
        Returns:
            bytes | None: Raw bytes, None on failure / non-image.
        """
        if url.startswith("data:image/") and ";base64," in url:
            try:
                return base64.b64decode(url.split(",", 1)[1])[: self.settings.max_image_bytes]
            except ValueError:
                return None
        if not url.startswith(("http://", "https://")):
            return None
        res = await self.http.get(
            url, verify=False, cache_ns="image", ttl=TTL["image"], error_ttl=3600,
            max_bytes=self.settings.max_image_bytes, retries=0, retry_on_connect=False,
        )
        if not res.ok or res.truncated or not res.content:
            return None
        ctype = res.headers.get("content-type", "")
        if "html" in ctype or "svg" in ctype:
            return None
        return res.content

    async def fingerprint(self, url: str, kind: str) -> ImageFingerprint | None:
        """
        Download and fingerprint one image.

        Args:
            url (str): Image URL.
            kind (str): "favicon", "logo", "og" or "screenshot".
        Returns:
            ImageFingerprint | None: Fingerprint, None if unusable.
        """
        data = await self._download(url)
        if not data:
            return None
        return await asyncio.to_thread(self.fingerprint_bytes, data, url, kind)

    def fingerprint_bytes(self, data: bytes, url: str, kind: str) -> ImageFingerprint | None:
        """
        Fingerprint raw image bytes (CPU work, run in a thread).

        Args:
            data (bytes): Image bytes.
            url (str): Source (for provenance).
            kind (str): Image kind.
        Returns:
            ImageFingerprint | None: Fingerprint, None if unusable/flat.
        """
        img = load_image(data)
        if img is None or is_flat(img):
            return None
        self.raw[url] = data
        return ImageFingerprint(
            url=url, kind=kind, phash=phash(img), dhash=dhash(img),
            width=img.width, height=img.height,
            mmh3=favicon_hash(data) if kind == "favicon" else None,
            sha256=hashlib.sha256(data).hexdigest(),
        )

    async def fingerprint_page(self, icon_urls: list[str], image_urls: list[str]) -> list[ImageFingerprint]:
        """
        Fingerprint the favicons and logo images of a page concurrently.

        Args:
            icon_urls (list[str]): Favicon URLs.
            image_urls (list[str]): Logo / og:image URLs.
        Returns:
            list[ImageFingerprint]: Usable fingerprints (duplicates removed).
        """
        jobs = [self.fingerprint(u, "favicon") for u in icon_urls[:3]]
        jobs += [self.fingerprint(u, "logo") for u in image_urls[:5]]
        out: list[ImageFingerprint] = []
        seen: set[str] = set()
        for fp in await asyncio.gather(*jobs):
            if fp is not None and fp.sha256 not in seen:
                seen.add(fp.sha256)
                out.append(fp)
        return out

    def compare(self, target: list[ImageFingerprint], candidate: list[ImageFingerprint]) -> VisualMatch:
        """
        Compare a candidate's images with the target brand images.

        Args:
            target (list[ImageFingerprint]): Target fingerprints.
            candidate (list[ImageFingerprint]): Candidate fingerprints.
        Returns:
            VisualMatch: Best similarity, exact favicon match, ORB score.
        """
        match = VisualMatch()
        fav = next((c for c in candidate if c.kind == "favicon"), None)
        match.favicon_mmh3 = fav.mmh3 if fav else None
        target_hashes = {t.sha256 for t in target} | {str(t.mmh3) for t in target if t.mmh3 is not None}
        for c in candidate:
            if c.sha256 in target_hashes or (c.mmh3 is not None and str(c.mmh3) in target_hashes):
                match.favicon_match = c.kind == "favicon" or match.favicon_match
                match.logo_similarity = 1.0
                match.matched_url = c.url
            for t in target:
                sim = hash_similarity(t, c)
                if sim > match.logo_similarity:
                    match.logo_similarity, match.matched_url = sim, c.url
        if self.settings.deep and self.orb_available and match.logo_similarity < 0.95:
            match.orb_similarity = self.orb_best(target, candidate)
        return match

    def orb_best(self, target: list[ImageFingerprint], candidate: list[ImageFingerprint]) -> float:
        """
        Best ORB keypoint similarity between target and candidate images.

        Args:
            target (list[ImageFingerprint]): Target fingerprints.
            candidate (list[ImageFingerprint]): Candidate fingerprints.
        Returns:
            float: Ratio of good matches in [0, 1] (0 without OpenCV).
        """
        if cv2 is None:
            return 0.0
        best = 0.0
        orb = cv2.ORB_create(nfeatures=500)
        matcher = cv2.BFMatcher(cv2.NORM_HAMMING)

        def features(url: str) -> tuple[list, object] | None:
            """
            Compute ORB keypoints/descriptors of a cached image.

            Args:
                url (str): Image URL (key of `self.raw`).
            Returns:
                tuple | None: (keypoints, descriptors) or None.
            """
            data = self.raw.get(url)
            img = load_image(data) if data else None
            if img is None:
                return None
            img.thumbnail((480, 480))
            gray = cv2.cvtColor(np.asarray(img), cv2.COLOR_RGB2GRAY)
            kp, des = orb.detectAndCompute(gray, None)
            return (kp, des) if des is not None and len(kp) >= 8 else None

        t_feats = [f for f in (features(t.url) for t in target if t.kind != "favicon") if f]
        for c in candidate:
            cf = features(c.url)
            if not cf:
                continue
            for tf in t_feats:
                pairs = matcher.knnMatch(tf[1], cf[1], k=2)
                good = sum(1 for p in pairs if len(p) == 2 and p[0].distance < 0.75 * p[1].distance)
                best = max(best, min(1.0, good / max(min(len(tf[0]), len(cf[0])), 1) * 2))
        return round(best, 4)


class Screenshotter:
    """
    Headless Chromium screenshots through Playwright (deep mode only).

    JavaScript runs inside an isolated, download-disabled browser context
    with HTTPS errors ignored; pages are closed after each capture.

    Args (constructor):
        out_dir (Path): Directory where screenshots are written.
        settings (Settings): User-Agent and proxy.
    """

    def __init__(self, out_dir: Path, settings: Settings) -> None:
        """
        Prepare (but do not launch) the browser.

        Args:
            out_dir (Path): Screenshot directory.
            settings (Settings): Scan configuration.
        Returns:
            None
        """
        self.out_dir = out_dir
        self.settings = settings
        self._pw = None
        self._browser = None
        self._context = None
        self._sem = asyncio.Semaphore(3)
        self.error: str | None = None

    async def start(self) -> bool:
        """
        Launch Chromium.

        Returns:
            bool: True when the browser is ready.
        """
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except ImportError:
            self.error = "playwright not installed"
            return False
        try:
            self._pw = await async_playwright().start()
            launch_args: dict = {"headless": True}
            if self.settings.proxy:
                launch_args["proxy"] = {"server": self.settings.proxy}
            self._browser = await self._pw.chromium.launch(**launch_args)
            self._context = await self._browser.new_context(
                viewport={"width": 1280, "height": 800}, ignore_https_errors=True,
                accept_downloads=False, user_agent=self.settings.user_agent,
                service_workers="block",
            )
            self.out_dir.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
            await self.close()
            return False

    async def capture(self, url: str, name: str) -> Path | None:
        """
        Screenshot one URL (viewport only).

        Args:
            url (str): Page URL.
            name (str): File stem (sanitised domain).
        Returns:
            Path | None: PNG path, None on failure.
        """
        if self._context is None:
            return None
        path = self.out_dir / f"{name}.png"
        async with self._sem:
            page = await self._context.new_page()
            try:
                activity.emit("browser", f"chromium --headless --screenshot={path.name} {url}")
                await page.goto(url, timeout=20_000, wait_until="load")
                await page.wait_for_timeout(1200)
                await page.screenshot(path=str(path), full_page=False)
                return path
            except Exception as exc:
                log.debug("screenshot %s failed: %s", url, exc)
                return None
            finally:
                await page.close()

    async def close(self) -> None:
        """
        Close the browser and Playwright driver.

        Returns:
            None
        """
        for obj, meth in ((self._context, "close"), (self._browser, "close"), (self._pw, "stop")):
            if obj is not None:
                try:
                    await getattr(obj, meth)()
                except Exception:
                    pass
        self._pw = self._browser = self._context = None
