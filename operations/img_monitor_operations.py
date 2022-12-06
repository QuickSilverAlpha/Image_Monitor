# Python3.6
# Author(s): Rohan Ahuja

import logging
import multiprocessing

from operations.monitor_proc.monitor import *
from operations.pa_proc.pa_process import *

class img_monitor_operations(object):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def init_image_mon(self):

        try:
            self.logger.info("Initiating img_mon processes!")
            # multiprocessing queues
            pa_queue = multiprocessing.Queue()

            # multiprocessing locks
            pa_lock = multiprocessing.Lock()

            # multiprocessing events
            pa_event = multiprocessing.Event()

            # initiating img_mon process

            self.logger.info("Initiating the monitoring process!")
            img_mon_process = multiprocessing.Process(name="img_mon_process",
                                                      target=monitor(pa_queue, pa_lock, pa_event)
                                                      .init_monitor)

            # initiating protection process

            self.logger.info("Initiating the protection process!")
            protection_process = multiprocessing.Process(name="protection_process",
                                                         target=pa_process(pa_queue, pa_lock, pa_event)
                                                         .init_pa)

            # Starting the img_mon processes

            img_mon_process.start()
            protection_process.start()

            # Waiting for all the processes to be complete
            img_mon_process.join()
            protection_process.join()

        except:
            self.logger.error("Failed to initiate img_mon processes!", exc_info=True)
