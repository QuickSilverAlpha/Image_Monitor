# Python3.6
# Author(s): Rohan Ahuja


class constants(object):

    logger_config_file = 'logger_config.json'
    img_mon_config_file = 'img_monitor_config.ini'

    pa_json_message_quarantine = {
        "type": "quarantine",
        "path": "pa/quarantine"
    }

    pa_json_message_malicious = {
        "type": "malicious",
        "path": "pa/malicious"
    }
