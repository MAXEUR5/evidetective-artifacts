import logging
import sys


def get_logger(name: str = "mini_feat", level: int = logging.INFO) -> logging.Logger:
    """Return a small, dependency-free logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create handler only once
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(h)
        logger.propagate = False

    return logger


slog = get_logger(level=logging.INFO)
