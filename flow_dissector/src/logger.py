import logging

__all__ = ['LOGGER']


LOGGER = logging.getLogger(f'dissector')
LOGGER.setLevel(level='INFO')
stream_handler = logging.StreamHandler()
formatter = logging.Formatter('[%(levelname)s] %(message)s')
stream_handler.setFormatter(formatter)
LOGGER.addHandler(stream_handler)
