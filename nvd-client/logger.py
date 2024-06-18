import logging

def setup_logger(name: str, log_file: str, level: int = logging.INFO) -> logging.Logger:
    """
    Set up a logger with the given name and log file.

    Args:
        name (str): The name of the logger.
        log_file (str): The file where logs will be written.
        level (int): The logging level. Default is logging.INFO.

    Returns:
        logging.Logger: The configured logger.
    """
    formatter = logging.Formatter('%(asctime)s %(name)s - line %(lineno)d - %(levelname)s: %(message)s')

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    # Configure the logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.addHandler(console_handler)

    return logger
