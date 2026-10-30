from html.parser import HTMLParser
from pathlib import Path
import base64
import hashlib
import re


class ResourceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.stylesheets = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("src", "").startswith("https://"):
            self.scripts.append(attrs)
        if tag == "link" and attrs.get("rel") == "stylesheet" and attrs.get("href", "").startswith("https://"):
            self.stylesheets.append(attrs)


def test_external_resources_are_pinned_and_integrity_checked():
    template = Path(__file__).parents[1] / "audithor_project/templates/dashboard.html"
    html = template.read_text()
    parser = ResourceParser()
    parser.feed(html)

    assert "https://cdn.tailwindcss.com" not in [resource["src"] for resource in parser.scripts]
    assert "vendor/tailwind-3.4.17.js" in html
    vendor = Path(__file__).parents[1] / "audithor_project/static/vendor/tailwind-3.4.17.js"
    assert vendor.exists()
    digest = base64.b64encode(hashlib.sha384(vendor.read_bytes()).digest()).decode()
    assert f"sha384-{digest}" == "sha384-igm5BeiBt36UU4gqwWS7imYmelpTsZlQ45FZf+XBn9MuJbn4nQr7yx1yFydocC/K"

    for resource in parser.scripts:
        assert re.search(r"(?:@|/)\d+\.\d+\.\d+(?:/|$)", resource["src"]), resource["src"]
        assert resource.get("integrity", "").startswith("sha384-")
        assert resource.get("crossorigin") == "anonymous"
        assert resource.get("referrerpolicy") == "no-referrer"

    for resource in parser.stylesheets:
        if "fonts.googleapis.com" in resource["href"]:
            assert resource.get("crossorigin") == "anonymous"
            assert resource.get("referrerpolicy") == "no-referrer"
        else:
            assert re.search(r"(?:@|/)\d+\.\d+\.\d+(?:/|$)", resource["href"])
            assert resource.get("integrity", "").startswith("sha384-")
            assert resource.get("crossorigin") == "anonymous"
            assert resource.get("referrerpolicy") == "no-referrer"


def test_dashboard_and_vendored_tailwind_are_served_by_flask():
    import audithor_app
    from conftest import make_client

    client = make_client(audithor_app.app)
    response = client.get("/")
    assert response.status_code == 200
    assert "/static/vendor/tailwind-3.4.17.js" in response.get_data(as_text=True)

    asset = client.get("/static/vendor/tailwind-3.4.17.js")
    assert asset.status_code == 200
    assert "javascript" in asset.content_type.lower()
