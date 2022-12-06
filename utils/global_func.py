# Python3.6
# Author(s): Rohan Ahuja

import os
import logging
import configparser

from constants import *

class global_func(object):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def fetch_config_file_path(self):

        config_file_path = None

        # fetching config file name

        try:
            config_file_name = constants().img_mon_config_file
            config_file_path = os.path.join(os.getcwd() + "/configurations/" + config_file_name)


        except:
            self.logger.error("Failed to fetch config file path!", exc_info=True)

        finally:
            return config_file_path


    def fetch_folder_to_monitor(self):
        try:
            folder_path = None
            # fetching config file name

            config_file_path = self.fetch_config_file_path()

            # fetching GRPC IP and port

            config = configparser.ConfigParser()
            if os.path.exists(config_file_path):
                config.read(config_file_path)

                self.logger.info("Fetching path of the folder to be monitored!")

                folder_path = config['MONITORING']['MONITOR_FOLDER']

                self.logger.info("Watched folder path: {}".format(folder_path))

            else:
                self.logger.critical("Watched folder path does not exist!")

            del config
            return folder_path

        except:
            self.logger.error("Failed to fetch the path of the monitored folder", exc_info=True)

    def fetch_pa_script_path(self):
        try:
            script_path = None
            # fetching config file name

            config_file_path = self.fetch_config_file_path()

            # fetching GRPC IP and port

            config = configparser.ConfigParser()
            if os.path.exists(config_file_path):
                config.read(config_file_path)

                self.logger.info("Fetching path of the protection action script!")

                script_path = config['PROTECTION']['PA_SCRIPT_PATH']

                self.logger.info("PA script path: {}".format(script_path))

            else:
                self.logger.error("PA script does not exist!")

            del config
            return script_path

        except:
            self.logger.error("Failed to fetch the path of the monitored folder", exc_info=True)

    def fetch_list_path(self, list_type):
        try:
            list_path = None
            # fetching config file name

            config_file_path = self.fetch_config_file_path()

            # fetching GRPC IP and port

            config = configparser.ConfigParser()
            if os.path.exists(config_file_path):
                config.read(config_file_path)

                self.logger.info("Fetching the {}list!".format(list_type))

                if list_type == "allow":
                    list_path = config['PROTECTION']['ALLOW_LIST']

                elif list_type == "deny":
                    list_path = config['PROTECTION']['DENY_LIST']

                list_path = os.path.join(os.getcwd(), list_path)

                self.logger.info("{}list path: {}".format(list_type, list_path))

            else:
                self.logger.critical("Image Monitor path does not exist!".format(list_type))

            del config
            return list_path

        except:
            self.logger.error("Failed to fetch {}list!".format(list_type), exc_info=True)

    def fetch_list(self, list_type):
        try:
            self.logger.info("Reading the {}list".format(list_type))
            checksum_dict = {}
            checksum_list = []

            list_path = self.fetch_list_path(list_type)
            with open(list_path, "r") as f_handle:
                checksum_list = f_handle.read().split('\n')
                if checksum_list[-1] == '':
                    checksum_list.pop()
                for checksum in checksum_list:
                    checksum_dict[checksum] = 'checksum'

            return checksum_dict
        except:
            self.logger.critical("Failed to fetch {}list".format(list_type), exc_info=True)
