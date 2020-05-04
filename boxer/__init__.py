#!/usr/bin/env python3

import logging

log_handler = logging.FileHandler("boxer.log", mode="w")
log_handler.setLevel(logging.DEBUG)
log_handler.setFormatter(
    logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    )

box_logger = logging.getLogger(__name__)

box_logger.addHandler(log_handler)
box_logger.setLevel(logging.DEBUG)
box_logger.propagate = False
