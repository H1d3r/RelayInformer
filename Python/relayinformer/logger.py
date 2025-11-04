import logging
from rich.logging import RichHandler

from relayinformer import console

OBJ_EXTRA_FMT = {
    "markup": True,
    "highlighter": False
}

FORMAT = "%(message)s"
logger = logging.getLogger("relayinformer")

handler = RichHandler(omit_repeated_times=False, show_path=False, keywords=[], console=console)
handler.setFormatter(logging.Formatter(FORMAT, datefmt="[%X]"))
logger.addHandler(handler)

logger.propagate = False