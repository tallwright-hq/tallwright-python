# SPDX-License-Identifier: Apache-2.0
"""One request to a door, over a channel that keeps its credential, and its answer as it came.

The recording door is ``POST <ingest>/v1/records`` (https://docs.tallwright.com/http): a bearer key, a body
of JSON lines with a Content-Length, at most 4 MiB. This module sends exactly one line and reports what
came back; deciding what an answer MEANS is the client's, so the rules for a refusal and for a
confirmation are in one place. The exhibit door's one-time link is opened here too (:func:`fetch`).

**HTTPS, or a door on this machine.** The key authorises appending to an evidence log, the one
permission whose abuse is invisible: a forged record is sealed and witnessed like a real one. An exhibit
link is a credential of its own: whoever holds it can take the exhibit. So neither travels in the clear,
except to a loopback address, where a door beside the caller is the point.

**The certificate is checked by this package's own context.** The standard library's HTTPS handler
takes the process-wide default context, which one line anywhere in a process can replace with one that
checks nothing. A context made here is not that line's to change.

**No proxy for a door on this machine.** The proxy variables of the environment apply to a request to
another host, where an https request is a tunnel the proxy cannot read. Applied to a loopback door they
would send the key and the line in the clear to whatever the variable names, so they are not applied.

**No redirect is followed.** A redirect carries the request to an address nobody configured, and the
standard library forwards an ``Authorization`` header with it. The key is sent as an unredirected
header, and a redirect comes back as the answer it is, so the caller sees the address it points to and
decides.

**No answer is believed past its size.** A receipt is a few hundred bytes; an answer beyond
:data:`MAX_ANSWER` is not read as one.

**The key is never a plain local.** It is held in a :class:`Key`, whose repr shows its first eleven
characters, the part a screen may show, and revealed only inside the expression that builds the header:
an error tracker that records local variables records the object, never the key.

**Nothing but a network failure leaves a request.** The standard library's frames hold the headers in
plain text, the key among them. An address it cannot send as written is refused before any request
(:func:`checked_address`); whatever else breaks in flight leaves as :class:`BrokeInFlight`, chained to
nothing, from a frame that no longer holds the request. A network failure is an ``OSError`` or an
``http.client.HTTPException`` every caller here describes and drops.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit

from tallwright_core.document import load_document

#: The door's one path. It is appended to the address the caller configured, which may name a book
#: beneath the host (``https://ingest.example/<book>``).
PATH = "/v1/records"
#: Far above any receipt, far below anything that costs memory.
MAX_ANSWER = 1 << 20
USER_AGENT = "tallwright-cloud/1.0.0rc1"


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _shown(parts: SplitResult) -> str:
    """What a message may say about an address: its scheme and host, never a path, a token or a user."""
    return f"{parts.scheme}://{parts.hostname or ''}" if parts.scheme else "an address without a scheme"


def checked_address(url: str, what: str) -> SplitResult:
    """``url``, split, if a request can go there as written, without misdirecting it or exposing a credential."""
    # Before splitting: the splitter drops a line break without a word, and the standard library sends
    # nothing beyond printable ASCII. The position says where, and repeats nothing of a link.
    odd = next((index for index, character in enumerate(url) if not "!" <= character <= "~"), None)
    if odd is not None:
        raise ValueError(
            f"{what}: its address holds U+{ord(url[odd]):04X} at position {odd}, which no address carries as "
            "written (a space, a line break or a character beyond ASCII, often pasted along with it): "
            "percent-encode it in a path, and write a host name beyond ASCII in its xn-- form"
        )
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or (parts.scheme == "http" and not is_loopback(parts.hostname or "")):
        raise ValueError(
            f"{_shown(parts)}: {what} is reached over https; plain http is for a door on this machine "
            "(localhost, 127.0.0.1, ::1) only, because a credential must not travel in the clear"
        )
    if not parts.hostname:
        raise ValueError(f"{what} names no host")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"{_shown(parts)}: {what} carries credentials in the address; nothing is sent that way")
    if parts.query or parts.fragment:
        raise ValueError(f"{_shown(parts)}: {what} carries a query or a fragment, and the door reads neither")
    try:
        port_usable = parts.port != 0
    except ValueError:
        port_usable = False
    if not port_usable:
        raise ValueError(f"{_shown(parts)}: {what} names a port no door listens on; a port is a number from 1 to 65535")
    try:
        # The resolver's own test of a name: every part between dots from 1 to 63 characters.
        parts.hostname.encode("idna")
    except UnicodeError:
        raise ValueError(
            f"{_shown(parts)}: {what} names a host with an empty part or a part longer than 63 characters"
        ) from None
    return parts


def endpoint(url: str) -> str:
    """The recording door's address under ``url``, or a refusal naming what would misdirect the key."""
    checked_address(url, "the recording door")
    return url.rstrip("/") + PATH


class Key:
    """The archive key, held so that no repr and no frame's locals show more than its face."""

    __slots__ = ("_key",)

    def __init__(self, key: object) -> None:
        if not isinstance(key, str) or not key or not all("!" <= c <= "~" for c in key):
            raise ValueError(
                "the key is the archive key exactly as it was shown once: printable ASCII, no spaces "
                "and no line breaks"
            )
        self._key = key

    def reveal(self) -> str:
        return self._key

    def binding(self) -> str:
        """A fingerprint the evidence marks pending records with: which key wrote them, not the key.

        Thirty-two hex digits of a hash under this package's own label, so it opens nothing anywhere
        else and says nothing about the key a guess could test cheaper than the door does.
        """
        return hashlib.sha256(b"tallwright-cloud evidence binding\x00" + self._key.encode("ascii")).hexdigest()[:32]

    def __repr__(self) -> str:
        return f"Key({self._key[:11] + '…' if len(self._key) >= 32 else '…'})"


@dataclass(frozen=True)
class Answer:
    """What came back: the status, and the body when it is one JSON object within the size bound."""

    status: int
    body: dict[str, Any] | None
    #: Where a redirect pointed, so the caller can see it; it is never followed.
    location: str | None = None


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        """Followed nowhere: urllib then raises the redirect as the HTTPError it is."""
        return None


class BrokeInFlight(OSError):
    """A request broke in flight in a way no network failure does, such as an encoding the standard
    library could not make. Said by the type of what broke, never by its message, which may quote a header."""


def object_in(data: bytes) -> dict[str, Any] | None:
    """The one JSON object an answer is, read within :data:`MAX_ANSWER` by the parser that refuses a
    repeated key and a nesting no stack follows; None for anything else."""
    if len(data) > MAX_ANSWER:
        return None
    try:
        body = load_document(data)
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


_TLS = ssl.create_default_context()


def opener_for(url: str) -> urllib.request.OpenerDirector:
    """The environment's proxies, as they are now, for another host; none at all for a door on this machine.

    Built per request: a proxy handler reads the environment when it is made, and one made at import
    would keep the proxies of a moment nobody chose.
    """
    if is_loopback(urlsplit(url).hostname or ""):
        return urllib.request.build_opener(
            NoRedirects, urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=_TLS)
        )
    return urllib.request.build_opener(NoRedirects, urllib.request.HTTPSHandler(context=_TLS))


def exchange(
    method: str, url: str, key: Key | None, data: bytes | None, content_type: str | None, timeout: float, limit: int
) -> tuple[int, bytes, str | None]:
    """One request, and its answer as it came: the status, at most ``limit`` + 1 bytes of the body, and
    where a redirect pointed. ``key``, when given, is the bearer, never carried to a redirect.

    A network failure is raised as it came: an ``OSError``, or an ``http.client.HTTPException`` for an
    answer that broke off or was not HTTP. Anything else is :class:`BrokeInFlight`.
    """
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("User-Agent", USER_AGENT)
    if content_type is not None:
        request.add_header("Content-Type", content_type)
    if key is not None:
        request.add_unredirected_header("Authorization", "Bearer " + key.reveal())
    try:
        try:
            with opener_for(url).open(request, timeout=timeout) as response:
                return int(response.status), response.read(limit + 1), None
        except urllib.error.HTTPError as answered:
            with answered:
                return int(answered.code), answered.read(limit + 1), answered.headers.get("Location")
    except (OSError, http.client.HTTPException):
        raise
    except Exception as failed:  # noqa: BLE001 - whatever it is, the frames it ran through hold the header
        broke = type(failed).__name__
    del request
    raise BrokeInFlight(f"{broke} broke the request in flight")


def post(url: str, key: Key, line: bytes, timeout: float) -> Answer:
    """Send ``line`` to the door once; a failure is raised as :func:`exchange` raises it."""
    status, body, location = exchange("POST", url, key, line, "application/x-ndjson", timeout, MAX_ANSWER)
    return Answer(status, object_in(body), location)


def fetch(url: str, timeout: float, limit: int, key: Key | None = None) -> tuple[int, bytes]:
    """GET ``url`` once, reading at most ``limit`` + 1 bytes: with no credential but the address itself
    (a link), or with ``key`` as the bearer (an export key). A failure is raised as :func:`exchange` raises it.
    """
    status, body, _ = exchange("GET", url, key, None, None, timeout, limit)
    return status, body


def said(answer: Answer) -> str | None:
    """The door's own sentence, when its answer carried one: its answers are JSON with an ``error``."""
    error = (answer.body or {}).get("error")
    return error if isinstance(error, str) else None


def said_in(body: bytes) -> str:
    """The door's own sentence in a body that may or may not be its JSON."""
    try:
        error = load_document(body).get("error")
    except (ValueError, AttributeError):
        error = None
    return error if isinstance(error, str) else "the answer carried no sentence"
