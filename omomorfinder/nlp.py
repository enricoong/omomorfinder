"""
Natural-language analysis of web page text.

  * A dependency-free TF-IDF engine (sublinear tf, smoothed idf, cosine)
    measures how much a lookalike site's text resembles the target's: very
    high similarity + brand = clone/phishing, high similarity without the
    brand = likely competitor.
  * Multilingual (Italian/English) phishing lexicon matching.
  * Optional semantic embeddings (sentence-transformers, multilingual
    MiniLM) in deep mode, downloaded automatically on first use.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
from collections import Counter
from typing import Any

from . import activity

log = logging.getLogger(__name__)

TOKEN_RE = re.compile(r"[^\W\d_]{3,}", re.UNICODE)

STOPWORDS: frozenset[str] = frozenset("""
the and for are but not you all any can had her was one our out has have from they this that
with your what when will more about which their there them then than been were into some would
other only also its over such most these those very just how why who whom where here each
il lo la gli le uno una del della dello dei degli delle nel nella nei nelle sul sulla sui
con per tra fra che chi cui non come dove quando anche ancora ogni tutto tutti tutte questo
questa questi queste quello quella sono essere stato stata hanno abbiamo siete sei suo sua
suoi sue loro nostro nostra vostro vostra più meno molto poco dal dalla dai dalle alla alle
agli allo ed od ma se già solo sia via cookie cookies privacy policy home menu copyright
reserved rights diritti riservati click qui here www com http https
""".split())

PHISHING_TERMS: tuple[str, ...] = (
    # English
    "login", "log in", "sign in", "password", "verify your", "verification",
    "account suspended", "account locked", "unlock", "confirm your", "update your",
    "billing", "payment details", "credit card", "card number", "cvv", "security alert",
    "unusual activity", "suspicious activity", "wallet", "seed phrase", "recovery phrase",
    "one-time", "otp", "2fa", "authenticate", "reset password", "invoice", "refund",
    # Italian
    "accedi", "accesso", "credenziali", "verifica", "conferma i tuoi", "aggiorna i tuoi",
    "account sospeso", "conto sospeso", "bloccato", "sblocca", "carta di credito",
    "numero carta", "codice di sicurezza", "codice otp", "attività sospetta", "rimborso",
    "pagamento", "home banking", "inserisci", "dati personali", "scadenza",
)


def tokenize(text: str) -> list[str]:
    """
    Lower-case word tokenisation without stop-words.

    Args:
        text (str): Arbitrary text (any language).
    Returns:
        list[str]: Tokens of at least 3 letters.
    """
    return [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS]


def phishing_keywords(text: str, limit: int = 12) -> list[str]:
    """
    Find phishing-related expressions in a text.

    Args:
        text (str): Page title + visible text.
        limit (int): Maximum number of expressions returned.
    Returns:
        list[str]: Matched expressions, in lexicon order.
    """
    low = text.lower()
    found = [term for term in PHISHING_TERMS if term in low]
    return found[:limit]


def title_terms(title: str, brand: str, limit: int = 4) -> list[str]:
    """
    Derive extra brand words from the target page title.

    Args:
        title (str): Target homepage title.
        brand (str): Brand label (always included first).
        limit (int): Maximum number of terms.
    Returns:
        list[str]: e.g. ["poste", "italiane"].
    """
    terms = [brand]
    for tok in tokenize(title):
        if tok not in terms and len(tok) >= 4:
            terms.append(tok)
        if len(terms) >= limit:
            break
    return terms


class TfidfIndex:
    """
    In-memory TF-IDF vector space over a small corpus of pages.

    Args (constructor):
        docs (dict[str, str]): Document id -> text.
    """

    def __init__(self, docs: dict[str, str]) -> None:
        """
        Build sparse TF-IDF vectors for every document.

        Args:
            docs (dict[str, str]): Document id -> text.
        Returns:
            None
        """
        counts = {doc_id: Counter(tokenize(text)) for doc_id, text in docs.items()}
        n_docs = max(len(counts), 1)
        df: Counter[str] = Counter()
        for c in counts.values():
            df.update(c.keys())
        idf = {term: math.log((1 + n_docs) / (1 + freq)) + 1.0 for term, freq in df.items()}
        self.vectors: dict[str, dict[str, float]] = {}
        for doc_id, c in counts.items():
            vec = {t: (1 + math.log(tf)) * idf[t] for t, tf in c.items()}
            norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
            self.vectors[doc_id] = {t: v / norm for t, v in vec.items()}

    def similarity(self, a: str, b: str) -> float:
        """
        Cosine similarity between two documents.

        Args:
            a (str): First document id.
            b (str): Second document id.
        Returns:
            float: Similarity in [0, 1] (0 if a document is unknown/empty).
        """
        va, vb = self.vectors.get(a), self.vectors.get(b)
        if not va or not vb:
            return 0.0
        if len(va) > len(vb):
            va, vb = vb, va
        return round(sum(w * vb.get(t, 0.0) for t, w in va.items()), 4)


class EmbeddingModel:
    """
    Optional multilingual sentence-embedding model (deep mode).

    The model is loaded lazily in a worker thread; if the
    `sentence-transformers` package is missing the class reports itself as
    unavailable and the pipeline continues with TF-IDF only.

    Args (constructor):
        model_name (str): Hugging Face model id.
    """

    DEFAULT = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"

    def __init__(self, model_name: str = DEFAULT) -> None:
        """
        Prepare (but do not load) the model.

        Args:
            model_name (str): Hugging Face model id.
        Returns:
            None
        """
        self.model_name = model_name
        self._model: Any = None
        self.error: str | None = None

    async def load(self) -> bool:
        """
        Load (downloading on first use) the model in a background thread.

        Returns:
            bool: True when the model is ready.
        """
        if self._model is not None:
            return True
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
        except ImportError:
            self.error = "sentence-transformers not installed"
            return False
        try:
            self._model = await asyncio.to_thread(SentenceTransformer, self.model_name)
            return True
        except Exception as exc:  # model download / torch errors
            self.error = f"{type(exc).__name__}: {exc}"
            return False

    async def similarities(self, reference: str, others: dict[str, str]) -> dict[str, float]:
        """
        Cosine similarity between a reference text and many others.

        Args:
            reference (str): Target page text.
            others (dict[str, str]): Document id -> text.
        Returns:
            dict[str, float]: Document id -> similarity in [0, 1].
        """
        if self._model is None or not others:
            return {}
        ids = list(others)
        texts = [reference[:4000]] + [others[i][:4000] for i in ids]
        activity.emit("nlp", f"embed {len(texts)} pages with {self.model_name.rsplit('/', 1)[-1]}")

        def encode() -> list[float]:
            """
            Encode all texts and compute cosine similarities to the first.

            Returns:
                list[float]: Similarity of each other text.
            """
            emb = self._model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
            ref = emb[0]
            return [float(max(0.0, min(1.0, (e * ref).sum()))) for e in emb[1:]]

        try:
            sims = await asyncio.to_thread(encode)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            return {}
        return {i: round(s, 4) for i, s in zip(ids, sims, strict=True)}
