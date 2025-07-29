import logging

def get_logger():
    logger = logging.getLogger("vaultLogger")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler("vault_activity_log.txt")
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
