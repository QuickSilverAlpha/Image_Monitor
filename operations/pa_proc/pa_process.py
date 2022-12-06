# Python3.6
# Authors: Rohan Ahuja, Ethan Bootehsaz

import os
import json
import queue
import logging
import subprocess


from utils.global_func import *
from constants import *

class pa_process(object):

    def __init__(self, pa_queue, pa_lock, pa_event):
        self.logger = logging.getLogger(__name__)

        # queues, events and locks

        self.pa_queue = pa_queue
        self.pa_lock = pa_lock
        self.pa_event = pa_event

        self.logger.info("Successfully initiated pa process process!")


    def init_pa(self):

        try:

            # Waiting for protection action signal

            self.logger.info("Protection Action process waiting for messages to act!")
            self.pa_event.wait()
            
            # Signal is received
            self.logger.info("Received signal! Initiating protection action!")

            # consuming messages from the pa queue till empty and executing protection action
            while self.pa_event.is_set():

                # reading from queue till empty

                while self.pa_queue.qsize() > 0:

                    self.logger.info("De-queuing from the pa internal queue!")

                    msg = None

                    # lock and dequeue

                    self.logger.debug("Acquiring lock on pa internal queue to de-queue!")

                    self.pa_lock.acquire()

                    try:

                        msg = self.pa_queue.get(timeout=2)

                    except queue.Empty:
                        self.logger.debug("Queue is empty!")

                    self.logger.debug("De-queue done! Releasing lock on pa internal queue!")

                    self.pa_lock.release()

                    if msg:

                        self.logger.debug(msg)
                        # loading the json
                        # msg = msg.decode('utf-8')
                        # json_msg = json.loads(msg)

                        self.trigger_pa(msg)
                    else:
                        self.logger.debug("No message to process!",
                                          extra={"msg_code": 110})

                # dispatched all to bus, going back into wait

                self.logger.info("All the messages processed successfully! "
                                 "Going back to wait state!", extra={"msg_code": 110})
                self.pa_event.clear()
                self.pa_event.wait()



        except:
            self.logger.info("Failed to initiate protection action!", exc_info=True)

    def trigger_pa(self, json_msg):
        try:

            dest_path = None
            src_path = None

            self.logger.info("Executing protection action!")

            if json_msg["type"] == "quarantine":
                dest_path = os.path.join(os.getcwd(), constants().pa_json_message_quarantine["path"])

            elif json_msg["type"] == "malicious":
                dest_path = os.path.join(os.getcwd(), constants().pa_json_message_malicious["path"])

            if json_msg.get("path", None):
                src_path = json_msg["path"]

            pa_script = os.path.join(os.getcwd(), global_func().fetch_pa_script_path())

            # command = "{} {} {}".format(pa_script, src_path, dest_path)

            output = subprocess.run([pa_script, src_path, dest_path], stdout=subprocess.PIPE)

            self.logger.info("[PA SCRIPT]: {}".format(str(output.stdout, "utf-8")))

            if output.returncode == 0:
                self.logger.info("Successfully executed the PA!")

            else:
                self.logger.error("Failed to execute the PA")

        except:
            self.logger.error("Failed to execute the protection action!", exc_info=True)
