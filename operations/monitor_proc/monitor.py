# Python3.6
# Author(s): Rohan Ahuja
# Reference: https://www.linode.com/docs/guides/monitor-filesystem-events-with-pyinotify/

import copy
import glob
import os.path
import queue
import hashlib
import logging
import pyinotify

from utils.global_func import *

class monitor(object):

    def __init__(self, pa_queue, pa_lock, pa_event):

        self.logger = logging.getLogger(__name__)

        # queues, events and locks

        self.pa_queue = pa_queue
        self.pa_lock = pa_lock
        self.pa_event = pa_event

        self.allowlist = global_func().fetch_list("allow")
        self.denylist = global_func().fetch_list("deny")

        self.watch_folder_path = global_func().fetch_folder_to_monitor()
        self.logger.info("Checking existing files against deny list!")
        self.initial_file_check()

        self.logger.info("Successfully initiated monitor process!")

    def init_monitor(self):
        try:
            # I
            for method in process_file_system_events._methods:
                event_monitor(process_file_system_events, method, self.pa_queue, self.pa_lock, self.pa_event)

            watch_manager = pyinotify.WatchManager()
            event_notifier = pyinotify.Notifier(watch_manager, process_file_system_events())

            watch_manager.add_watch(self.watch_folder_path, pyinotify.ALL_EVENTS)
            event_notifier.loop()


        except:
            self.logger.info("Failed to initiate monitoring!", exc_info=True)
            
    def initial_file_check(self):
        try:
            file_list = glob.glob(self.watch_folder_path + "/*")
            for file in file_list:
                if os.path.isfile(file):
                    checksum = self.compute_checksum(file)

                    if self.denylist.get(checksum, None):
                        self.logger.critical("DENYLISTED IMAGE FOUND {}. INITIATING PA!")
                        json_msg = copy.deepcopy(constants().pa_json_message_malicious)
                        json_msg["path"] = file

                        # Dispatch message to protection action process queue
                        self.logger.info("Dispatching event to PA process to take relevant action!")
                        self.dispatch_msg_to_pa(json_msg)
        except:
            self.logger.error("Failed to check the files against denylist!", exc_info=True)

    def compute_checksum(self, file_path):

        self.logger.info("Computing checksum of {}".format(file_path))
        try:
            checksum = None
            with open(file_path, "rb") as f_handle:
                bytes = f_handle.read()  # read file as bytes
                checksum = hashlib.sha256(bytes).hexdigest()
            return checksum
        except:
            self.logger.error("Failed to compute the checksum!", exc_info=True)

    def dispatch_msg_to_pa(self, json_msg):
        try:
            self.logger.info("Enqueuing message to PA queue!")

            # lock and enqueue

            self.logger.debug("Acquiring lock on PA queue to enqueue!")

            self.pa_lock.acquire()

            self.pa_queue.put(json_msg, timeout=2)

            self.logger.debug("Enqueue successful! Releasing lock on PA queue!")

            self.pa_lock.release()

            # Signaling PA process

            self.logger.debug("Signalling PA process!")

            self.pa_event.set()

        except:
            self.logger.info("Failed to dispatch message to the PA process!", exc_info=True)

def event_monitor(cls, method, pa_queue, pa_lock, pa_event):
    logger = logging.getLogger(__name__)

    def _id_and_dispatch_to_pa(self, event):
        try:
            logger.info("Method name: process_{}() Path name: {} Event Name: {}".format(method, event.pathname,
                                                                                        event.maskname))

            # Handling events and dispatching them to protection process for protection actions

            # Handle folder delete scenarios
            if event.maskname == "IN_DELETE|IN_ISDIR":
                logger.critical("SOMETHING IS FISHY! DIRECTORY {} DELETED!".format(event.pathname))

            # Handle file delete scenarios
            elif event.maskname == "IN_DELETE":
                logger.critical("SOMETHING IS FISHY! ALLOWED IMAGE {} DELETED!".format(event.pathname))

            # Handle scenarios around files moved to the monitored folders
            elif event.maskname == "IN_MOVED_TO":
                logger.critical("UNIDENTIFIED FILE MOVED TO THE MONITORED FOLDER: {}".format(event.pathname))
                json_msg = constants().pa_json_message_quarantine
                json_msg["path"] = event.pathname

                # Dispatch message to protection action process queue
                logger.info("Dispatching event to PA process to take relevant action!")
                monitor(pa_queue, pa_lock, pa_event).dispatch_msg_to_pa(json_msg)

            # Handle event on the file close after write. Not considering the IN_CLOSE_NOWRITE
            elif event.maskname == "IN_CLOSE_WRITE":
                logger.critical("UNIDENTIFIED FILE CREATED/ MODIFIED IN THE MONITORED FOLDER: {}".
                                format(event.pathname))
                json_msg = constants().pa_json_message_quarantine
                json_msg["path"] = event.pathname

                # Dispatch message to protection action process queue
                logger.info("Dispatching event to PA process to take relevant action!")
                monitor(pa_queue, pa_lock, pa_event).dispatch_msg_to_pa(json_msg)

        except:
            logger.error("Failed to identify the event and dispatch to PA!", exc_info=True)

    _id_and_dispatch_to_pa.__name__ = "process_{}".format(method)
    setattr(cls, _id_and_dispatch_to_pa.__name__, _id_and_dispatch_to_pa)

class process_file_system_events(pyinotify.ProcessEvent):
    _methods = ["IN_CREATE",
                "IN_OPEN",
                "IN_ACCESS",
                "IN_ATTRIB",
                "IN_CLOSE_NOWRITE",
                "IN_CLOSE_WRITE",
                "IN_DELETE",
                "IN_DELETE_SELF",
                "IN_IGNORED",
                "IN_MODIFY",
                "IN_MOVE_SELF",
                "IN_MOVED_FROM",
                "IN_MOVED_TO",
                "IN_Q_OVERFLOW",
                "IN_UNMOUNT",
                "default"]
