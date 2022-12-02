# Python3.6
# Author(s): Rohan Ahuja

import os
import sys
import json
import traceback
import socket
import logging.config
import logging.handlers as handlers

from utils.global_func import *
from operations.img_monitor_operations import *

logger = logging.getLogger(__name__)

# Defining the log filter to fetch the hostname
class ContextFilter(logging.Filter):

    hostname = socket.gethostname()
    def filter(self, record):
        record.hostname = ContextFilter.hostname
        return True

# The function will set up the logger
def setup_logging(
        default_path='logging.json',
        default_level=logging.DEBUG,
        env_key='LOG_CFG'):

    """Setup logging configuration

    """
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):

        with open(path, 'rt') as f:
            config = json.load(f)
            log_file_path = config["handlers"]["file_handler"]["filename"]
            config["filters"] = {"hostname_filter": {"()": ContextFilter}}
        logging.config.dictConfig(config)
        '''setting max log size for rotation is 30MB'''
        maxbytes = 30*1024*1024
        ''' setting log rotation file to 10'''
        backupcount = 10
        logHandler = handlers.RotatingFileHandler(log_file_path, maxBytes=maxbytes, backupCount=backupcount)
        stdout_handler = logging.StreamHandler(sys.stdout)
        logger.addHandler(logHandler)
        logger.addHandler(stdout_handler)

    else:
        logging.basicConfig(level=default_level)


if __name__ == '__main__':

    try:

        # Setting up logger

        logger_file_name = constants().logger_config_file
        logger_config_file_path = os.path.join(os.getcwd() + "/configurations/" + logger_file_name)
        setup_logging(logger_config_file_path)

        # Initiate Operations
        img_monitor_operations()

    except:
        traceback.print_exc()
    finally:
        logger.removeHandler(logger.handlers)
        logging.shutdown()
        os._exit(0)
