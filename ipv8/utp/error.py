from dataclasses import dataclass
from enum import Enum


class UTPErrorCode(Enum):
    NO_ERROR = 0
    CONNECTION_RESET = 1


@dataclass
class UTPError:
    code: UTPErrorCode = UTPErrorCode.NO_ERROR
    message: str = ""
