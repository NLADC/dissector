import logging


class CustomConsoleFormatter(logging.Formatter):
    """
    Color formatting for the logger
    """
    def format(self, record):
        formatter = "%(levelname)s - %(message)s"
        if record.levelno == logging.INFO:
            green = '\033[32m'
            reset = "\x1b[0m"
            log_fmt = green + formatter + reset
            self._style._fmt = log_fmt
            return super().format(record)
        if record.levelno == logging.DEBUG:
            cyan = '\033[36m'
            reset = "\x1b[0m"
            log_fmt = cyan + formatter + reset
            self._style._fmt = log_fmt
            return super().format(record)
        if record.levelno == logging.ERROR:
            magenta = '\033[35m'
            reset = "\x1b[0m"
            log_fmt = magenta + formatter + reset
            self._style._fmt = log_fmt
            return super().format(record)
        if record.levelno == logging.WARNING:
            yellow = '\033[33m'
            reset = "\x1b[0m"
            log_fmt = yellow + formatter + reset
            self._style._fmt = log_fmt
        else:
            self._style._fmt = formatter
        return super().format(record)


def get_logger(debug: bool = False, verbose: bool = False, logfile: str = 'dissector.log') -> logging.Logger:
    """
    Get a logger instance
    Args:
        debug: Show debug log messages
        verbose: Show more verbose messages (info)
        logfile: File to write log statements to

    Returns: logger
    """
    logger = logging.getLogger(__name__)

    # add custom formatter
    my_formatter = CustomConsoleFormatter()

    # Create handlers
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(my_formatter)

    # enable file logging when verbose/debug is set
    if debug or verbose:
        file_handler = logging.FileHandler(logfile)
        if debug:
            logger.setLevel(logging.DEBUG)
            file_handler.setLevel(logging.DEBUG)
        elif verbose:
            logger.setLevel(logging.INFO)
            file_handler.setLevel(logging.INFO)

        f_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)")
        file_handler.setFormatter(f_format)
        logger.addHandler(file_handler)

    # add handlers to the logger
    logger.addHandler(console_handler)

    return logger
