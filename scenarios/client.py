"""HTTP client for scenarios. It only talks to the lab's account service.

Each client has a synthetic origin (IP, network, country, device) sent as
X-Lab-Sim-* headers, which the app honours only inside the lab network.
"""
import http.cookies
import json
import random
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# The account service container on the internal lab network. Nothing else.
ALLOWED_HOSTS = {"app"}


class TargetRefused(SystemExit):
    pass


def check_target(base_url: str) -> str:
    host = urllib.parse.urlparse(base_url).hostname
    if host not in ALLOWED_HOSTS:
        raise TargetRefused(f"Refusing target {base_url!r}: scenarios only run against the lab app (http://app:8000).")
    return base_url.rstrip("/")


@dataclass
class Origin:
    """Where a simulated request comes from. IPs are from documentation ranges (RFC 5737)."""
    label: str
    country: str
    lat: float
    lon: float
    ip_type: str
    asn: int
    device: str
    ip: str = ""
    user_agent: str = "Mozilla/5.0 (LabScenario)"

    def __post_init__(self):
        if not self.ip:
            net = random.choice(["192.0.2", "198.51.100", "203.0.113"])
            self.ip = f"{net}.{random.randint(2, 254)}"

    def headers(self) -> dict:
        return {
            "X-Lab-Sim-IP": self.ip,
            "X-Lab-Sim-ASN": str(self.asn),
            "X-Lab-Sim-IP-Type": self.ip_type,
            "X-Lab-Sim-Geo": f"{self.country};{self.lat};{self.lon}",
            "X-Lab-Sim-Device": self.device,
            "User-Agent": self.user_agent,
        }


PLACES = {
    "CA": ("Montreal", 45.50, -73.57),
    "US": ("Boston", 42.36, -71.06),
    "FR": ("Paris", 48.86, 2.35),
    "NL": ("Amsterdam", 52.37, 4.90),
    "RO": ("Bucharest", 44.43, 26.10),
    "BR": ("Sao Paulo", -23.55, -46.63),
}


def home(country: str = "CA", device: str = "home-laptop") -> Origin:
    city, lat, lon = PLACES[country]
    return Origin(f"home ({city})", country, lat, lon, "residential", 64501, device,
                  user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) LabHome")


def datacenter(country: str = "RO", device: str = "attacker-vps") -> Origin:
    city, lat, lon = PLACES[country]
    return Origin(f"datacenter ({city})", country, lat, lon, "datacenter", 64512, device,
                  user_agent="python-requests/2.31 LabAttacker")


def residential(country: str, device: str) -> Origin:
    city, lat, lon = PLACES[country]
    return Origin(f"residential ({city})", country, lat, lon, "residential", 64502, device,
                  user_agent="Mozilla/5.0 (X11; Linux x86_64) LabOther")


@dataclass
class Response:
    status: int
    body: object

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def code(self) -> str:
        if isinstance(self.body, dict):
            detail = self.body.get("detail")
            if isinstance(detail, dict):
                return detail.get("code", "")
            return str(self.body.get("status", ""))
        return ""


@dataclass
class LabClient:
    base_url: str
    run_id: str
    origin: Origin | None = None
    admin_token: str | None = None
    cookies: dict = field(default_factory=dict)
    last_set_cookies: list = field(default_factory=list)

    def __post_init__(self):
        self.base_url = check_target(self.base_url)

    def call(self, method: str, path: str, body=None) -> Response:
        headers = {"Content-Type": "application/json", "X-Lab-Run-Id": self.run_id}
        if self.origin:
            headers.update(self.origin.headers())
        if self.admin_token:
            headers["X-Lab-Admin-Token"] = self.admin_token
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                status, raw, set_cookies = r.status, r.read(), r.headers.get_all("Set-Cookie") or []
        except urllib.error.HTTPError as e:
            status, raw, set_cookies = e.code, e.read(), e.headers.get_all("Set-Cookie") or []
        # Keep cookies by hand: the lab's Secure cookies must still work over plain HTTP here.
        self.last_set_cookies = list(set_cookies)
        for header in set_cookies:
            jar = http.cookies.SimpleCookie()
            jar.load(header)
            for name, morsel in jar.items():
                if morsel.value in ("", '""') or morsel["max-age"] == "0":
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = morsel.value
        try:
            parsed = json.loads(raw or b"null")
        except ValueError:
            parsed = raw.decode(errors="replace")[:200]
        return Response(status, parsed)

    def get(self, path: str) -> Response:
        return self.call("GET", path)

    def post(self, path: str, body=None) -> Response:
        return self.call("POST", path, body if body is not None else {})

    def put(self, path: str, body) -> Response:
        return self.call("PUT", path, body)
