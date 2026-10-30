from flask.testing import FlaskClient


class HostBoundClient(FlaskClient):
    def open(self, *args, **kwargs):
        headers = dict(kwargs.get("headers") or {})
        headers.setdefault("Host", "127.0.0.1:5001")
        kwargs["headers"] = headers
        return super().open(*args, **kwargs)


def make_client(app):
    app.test_client_class = HostBoundClient
    return app.test_client()
