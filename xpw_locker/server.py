# coding:utf-8

from http.server import ThreadingHTTPServer
import os
from typing import MutableMapping
from typing import Optional
from typing import Tuple

from xhtml import LocaleTemplate
from xkits_command import Command
from xpw import AuthInit
from xpw import BasicAuth
from xpw import SessionKeys
from xserver.http.proxy import HttpProxy
from xserver.http.proxy import RequestProxy
from xserver.http.proxy import ResponseProxy

BASE: str = os.path.dirname(__file__)


# @APP.before_request
# def authenticate() -> Optional[Any]:
#     Command().logger.debug("request.headers:\n%s", request.headers)
#     host: Optional[str] = request.headers.get("Host")
#     if host == f"localhost:{PORT}":
#         Command().logger.debug("Skip python-requests.")
#         return None
#     session_id: Optional[str] = request.cookies.get("session_id")
#     if session_id is None:
#         response = redirect(url_for("proxy", path=request.path.lstrip("/")))
#         response.set_cookie("session_id", SESSIONS.search().name)
#         return response
#     Command().logger.debug("%s request verify.", session_id)
#     if SESSIONS.verify(session_id):
#         # Command().logger.info("%s is logged.", session_id)
#         return None  # logged
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]
#         if not password:  # invalid password
#             Command().logger.info("%s login to %s with empty password.", session_id, username)  # noqa:E501
#         elif AUTH.verify(username, password):
#             SESSIONS.sign_in(session_id)
#             Command().logger.info("%s sign in with %s.", session_id, username)
#             return redirect(url_for("proxy", path=request.path.lstrip("/")))
#         Command().logger.warning("%s login to %s error.", session_id, username)
#     Command().logger.debug("%s need to login.", session_id)
#     context = TEMPLATE.search(request.headers.get("Accept-Language", "en"), "login").fill()  # noqa:E501
#     return render_template_string(TEMPLATE.seek("login.html").loads(), **context)  # noqa:E501


# @APP.route("/favicon.ico", methods=["GET"])
# def favicon() -> Response:
#     if (response := PROXY.request(request)).status_code == 200:
#         return response
#     session_id: Optional[str] = request.cookies.get("session_id")
#     logged: bool = isinstance(session_id, str) and SESSIONS.verify(session_id)
#     binary: bytes = TEMPLATE.seek("unlock.ico" if logged else "locked.ico").loadb()  # noqa:E501
#     return APP.response_class(binary, mimetype="image/vnd.microsoft.icon")


class AuthRequestProxy(RequestProxy):
    TEMPLATE = LocaleTemplate(os.path.join(BASE, "resources"))

    def __init__(self, target_url: str, lifetime: int = 86400, auth: Optional[BasicAuth] = None):  # noqa:E501
        self.__sessions: SessionKeys = SessionKeys(lifetime=lifetime)
        self.__auth: BasicAuth = auth or AuthInit.from_file()
        super().__init__(target_url)

    @property
    def auth(self) -> BasicAuth:
        return self.__auth

    @property
    def sessions(self) -> SessionKeys:
        return self.__sessions

    def authenticate(self, path: str, method: str, data: bytes,
                     headers: MutableMapping[str, str]
                     ) -> Optional[ResponseProxy]:
        Command().logger.debug("headers:\n%s", headers)
        # host: Optional[str] = request.headers.get("Host")
        # if host == f"localhost:{PORT}":
        #     Command().logger.debug("Skip python-requests.")
        #     return None
        session_id: Optional[str] = cookies.get("session_id")
        if session_id is None:
            #     response = redirect(url_for("proxy", path=request.path.lstrip("/")))
            #     response.set_cookie("session_id", SESSIONS.search().name)
            return response
        Command().logger.debug("%s request verify.", session_id)
        if self.sessions.verify(session_id):
            # Command().logger.info("%s is logged.", session_id)
            return None  # logged
        if method == "POST":
            username = request.form["username"]
            password = request.form["password"]
            if not password:  # invalid password
                Command().logger.info("%s login to %s with empty password.", session_id, username)  # noqa:E501
            elif self.auth.verify(username, password):
                self.sessions.sign_in(session_id)
                Command().logger.info("%s sign in with %s.", session_id, username)
                return redirect(path)
            Command().logger.warning("%s login to %s error.", session_id, username)
        Command().logger.debug("%s need to login.", session_id)
        context = self.TEMPLATE.search(headers.get("Accept-Language", "en"), "login").fill()  # noqa:E501
        return self.TEMPLATE.seek("login.html").render(**context)

    def request(self, *args, **kwargs) -> ResponseProxy:
        return self.authenticate(*args, **kwargs) or super().request(*args, **kwargs)  # noqa:E501


def run(listen_address: Tuple[str, int], request_proxy: AuthRequestProxy):
    httpd = ThreadingHTTPServer(listen_address, lambda *args: HttpProxy(*args, request_proxy=request_proxy))  # noqa:E501
    httpd.serve_forever()


if __name__ == "__main__":
    run(("0.0.0.0", 3000), AuthRequestProxy("https://example.com/"))
