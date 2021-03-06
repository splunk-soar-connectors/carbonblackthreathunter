from logging import handlers
import logging
import os
import sys
import re


class KennyLoggins:
    """ Base Class for Logging """

    def __init__(self, **kwargs):
        """Construct an instance of the Logging Object"""

    def get_logger(self, app_name=None, file_name="kenny_loggins", log_level=logging.INFO, version="unknown"):
        log_location = "{}{}".format(os.path.sep, os.path.join("var", "log", "phantom", "apps", app_name))
        _log = logging.getLogger("{}/{}".format(app_name, file_name))
        _log.propogate = False
        _log.setLevel(log_level)
        formatter = logging.Formatter(
            '%(asctime)s log_level=%(levelname)s pid=%(process)d tid=%(threadName)s \
             file="%(filename)s" function="%(funcName)s" line_number="%(lineno)d" version="{}" %(message)s'.format(
                version))
        try:
            if not os.path.isdir(log_location):
                os.makedirs(log_location)
            output_file_name = os.path.join(log_location, "{}.log".format(file_name))
            f_handle = handlers.RotatingFileHandler(output_file_name, maxBytes=25000000, backupCount=5)
            f_handle.setFormatter(formatter)
            if not len(_log.handlers):
                _log.addHandler(f_handle)
        except Exception as e:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(log_level)
            handler.setFormatter(formatter)
            if not len(_log.handlers):
                _log.addHandler(handler)
            _log.error("Failed to create file-based logging. {}".format(e))
        finally:
            return _log


class aplutils:

    def __init__(self):
        kl = KennyLoggins()
        self._log = kl.get_logger(app_name="apl_utils", file_name="apl_utils")

    def _check_single_validation(self, validation_item, string):
        self._log.info("check_single validation_item={} string={}".format(validation_item, string))
        pattern = re.compile(validation_item.get("regex", ".*"))
        does_not_match = True if validation_item.get("op", "does_not_match") == "does_not_match" else False
        # If search is None , then it did not match
        found_match = pattern.search(string)
        if (found_match is None and does_not_match) or (found_match is not None and not does_not_match):
            return validation_item.get("message", "Failed regex: {}".format(validation_item.get("regex", ".*")))
        return False

    def _validate_configuration(self, item, item_config, key):
        self._log.info("validating_config item={} item_config={} key={}".format(item, item_config, key))
        if "validation" not in item_config:
            return False
        if not item_config.get("required", False) and not item:
            return False
        si = ["{}: {}".format(key, x) for x in
              [self._check_single_validation(x, item) for x in item_config.get("validation")] if x]
        if len(si) < 1:
            return False
        return ", ".join(si)

    def validate_app_configuration(self, ac, config):
        ret_val = [self._validate_configuration(config.get(x, ""), ac[x], x) for x in ac]
        self._log.info("validating_config return={}".format(ret_val))
        return ret_val
