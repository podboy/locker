# coding:utf-8

from errno import ECANCELED
import os
from typing import Optional
from typing import Sequence
from typing import Tuple

from xkits_command import ArgParser
from xkits_command import Command
from xkits_command import CommandArgument
from xkits_command import CommandExecutor
from xpw import AuthInit
from xpw import BasicAuth
from xpw import DEFAULT_CONFIG_FILE

from xpw_locker.attribute import __description__
from xpw_locker.attribute import __urlhome__
from xpw_locker.attribute import __version__
from xpw_locker.server import AuthRequestProxy
from xpw_locker.server import run


@CommandArgument("locker", description=__description__)
def add_cmd(_arg: ArgParser):
    _arg.add_argument("--config", type=str, dest="config_file",
                      help="Authentication configuration", metavar="FILE",
                      default=os.getenv("CONFIG_FILE", DEFAULT_CONFIG_FILE))
    _arg.add_argument("--expires", type=int, dest="lifetime",
                      help="Session login interval hours", metavar="HOUR",
                      default=int(os.getenv("EXPIRES", "1")))
    _arg.add_argument("--target", type=str, dest="target_url",
                      help="Proxy target url", metavar="URL",
                      default=os.getenv("TARGET_URL", "http://localhost"))
    _arg.add_argument("--host", type=str, dest="listen_address",
                      help="Listen address", metavar="ADDR",
                      default=os.getenv("LISTEN_ADDRESS", "0.0.0.0"))
    _arg.add_argument("--port", type=int, dest="listen_port",
                      help="Listen port", metavar="PORT",
                      default=int(os.getenv("LISTEN_PORT", "3000")))


@CommandExecutor(add_cmd)
def run_cmd(cmds: Command) -> int:
    target_url: str = cmds.args.target_url
    lifetime: int = cmds.args.lifetime * 3600
    auth: BasicAuth = AuthInit.from_file(cmds.args.config_file)
    listen_address: Tuple[str, int] = (cmds.args.listen_address, cmds.args.listen_port)  # noqa:E501
    request_proxy: AuthRequestProxy = AuthRequestProxy(target_url=target_url, lifetime=lifetime, auth=auth)  # noqa:E501
    run(listen_address=listen_address, request_proxy=request_proxy)
    return ECANCELED


def main(argv: Optional[Sequence[str]] = None) -> int:
    cmds = Command()
    cmds.version = __version__
    return cmds.run(root=add_cmd, argv=argv, epilog=f"For more, please visit {__urlhome__}.")  # noqa:E501
