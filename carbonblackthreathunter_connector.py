# File: carbonblackthreathunter_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

import json

# Phantom App imports
import phantom.app as phantom
import sys
# Usage of the consts file is recommended
# from carbonblackthreathunter_consts import *
import time
import requests
from cb_client import cb_psc_client
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
import os
import shutil
import zipfile
import uuid
from phantom.vault import Vault
import magic
import re
import ipaddress
from utilities import KennyLoggins, logging, aplutils


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CarbonBlackThreathunterConnector(BaseConnector):
    MAGIC_FORMATS = [
        (
            re.compile('^PE.* Windows'), ['pe file'], '.exe'),
        (
            re.compile('^MS-DOS executable'), ['pe file'], '.exe'),
        (
            re.compile('^PDF '), ['pdf'], '.pdf'),
        (
            re.compile('^MDMP crash'), ['process dump'], '.dmp'),
        (
            re.compile('^Macromedia Flash'), ['flash'], '.flv'),
        (
            re.compile('^tcpdump capture'), ['pcap'], '.pcap')]

    def __init__(self):
        # Call the BaseConnectors init first
        super(CarbonBlackThreathunterConnector, self).__init__()
        self._state = None
        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._directory = None
        self.authorization_header = None
        self.user_agent_header = None
        self.version = "not_yet_loaded"
        self.client = None
        self._feed_state = None
        self.apl_utils = aplutils()
        self._action_functions = {'test_connectivity': self._handle_test_connectivity,
                                  'get_file': self._handle_get_file,
                                  'live_response': self._handle_live_response,
                                  'run_query': self._handle_run_query,
                                  'threat_feed': self._handle_threat_feed,
                                  'get_file_metadata': self._handle_get_file_metadata,
                                  'get_single_feed': self._handle_get_single_feed,
                                  'get_all_feeds': self._handle_get_all_feeds,
                                  'get_feed_reports': self._handle_get_feed_report,
                                  'delete_feed': self._handle_delete_feed,
                                  'create_report_ioc': self._handle_update_report_ioc,
                                  'delete_report_ioc': self._handle_delete_report_ioc_id,
                                  'delete_ioc_value': self._handle_delete_report_ioc
                                  }
        kl = KennyLoggins()
        self._log = kl.get_logger(app_name="phcarbonblackthreathunter", file_name="connector",
                                  log_level=logging.DEBUG, version=self.version)
        self._log.info("initialize_client=complete")

    def _is_ip(self, input_ip_address, action_result):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """
        ip_address_input = input_ip_address

        try:
            ipaddress.ip_address(unicode(ip_address_input))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid IP: {0}".format(e))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_report_ioc(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        exists, container_info, response_code = self.get_container_info()
        container_type = container_info.get("container_type", "default")

        ipv4 = param.get('ipv4_ioc')
        ipv6 = param.get('ipv6_ioc')
        domain = param.get('domain_ioc')
        hash = param.get('hash_ioc')

        if not (ipv4 or ipv6 or domain or hash):
            return action_result.set_status(phantom.APP_ERROR, "Atleast one parameter needs to be provided")
        if param.get('ipv4_ioc'):
            ret_val = self._is_ip(ipv4, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        if param.get('ipv6_ioc'):
            ret_val = self._is_ip(ipv6, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        try:
            if not container_type == "case":
                self._log.error("container_type={}".format(container_type))
                # TODO: Make this more visible in the interface.
                raise Exception("Container is not a case - {}".format(container_type))

            self._log.debug("container_info={}".format(json.dumps(container_info)))
            feed_id = self._feed_state.get("feed_id")
            report_hash = container_info.get("hash")
            report = None
            try:
                report = self.client.get_feed_report(feed_id, report_hash).get("report")
                self._log.debug("report={}".format(report))
            except Exception as e:
                self._log.warn("feed_id={} report_hash={} report_feed_error={}".format(feed_id, report_hash, e))

            if report is not None:
                iocsv2 = report.get("iocs_v2", [])
                field_map = {"ipv4_ioc": "netconn_ipv4",
                             "ipv6_ioc": "netconn_ipv6",
                             "domain_ioc": "netconn_domain",
                             "hash_ioc": "hash"}
                reverse_field_map = {v: k for k, v in field_map.items()}

                def process_delete_ioc(self, ioc):
                    param_key = reverse_field_map.get(ioc.get("field", {}), "not_found")
                    param_value = param.get(param_key, "")
                    self._log.debug("action=using_param_key param_key={} ioc_field={}".format(param_key,
                                                                                              ioc.get("field", {})))
                    # Check The IOC to see if it exists in the parameters sent from Phantom
                    if param_value is not None:
                        self._log.debug("action=not_none_param_key param={} param_key={}".format(param.get(param_key),
                                                                                                 param_key))
                        # If it exists in the param AND the IOC, delete param value from IOC
                        ioc_values = ioc.get("values", [])
                        if param_value in ioc_values:
                            self._log.debug("action=value_in_ioc_values values={} param_key={}".format(ioc_values,
                                                                                                       param_key))
                            # if the parameter is not in the ioc, append it to the list
                            while param_value in ioc_values:
                                ioc_values.remove(param_value)
                            ioc["values"] = ioc_values
                    return ioc

                if iocsv2 is None:
                    raise Exception("There is no ioc value in feed report to delete")
                else:
                    report["iocs_v2"] = [process_delete_ioc(self, ioc) for ioc in iocsv2]
                    report["timestamp"] = time.time()
                    self.client.update_feed_report(feed_id, report)
                    self._log.debug(
                        "report={} param={}".format(json.dumps(report),
                                                    json.dumps(param)))
                    self.save_progress("Delete for IOCs: {} {}".format(feed_id, report))
                    [action_result.add_data(x) for x in report.get("iocs_v2", [])]
                    return action_result.set_status(phantom.APP_SUCCESS, "Delete Report IOC Completed")
            else:
                self.save_progress("Delete IOC: No Report Found")
                return action_result.set_status(phantom.APP_SUCCESS, "Delete IOC: No Report Found")

        except Exception as e:
            if "'NoneType' object has no attribute 'get'" in e.message:
                return action_result.set_status(phantom.APP_ERROR, "Found invalid org_key value in configuration parameters")
            self._log.error("Update Report IOC: {}".format(e))
            return action_result.set_status(phantom.APP_ERROR, "Error occured while deleteing IOC value from the report: {}".format(str(e)))

    def _handle_delete_report_ioc_id(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        exists, container_info, response_code = self.get_container_info()
        container_type = container_info.get("container_type", "default")
        try:
            if not container_type == "case":
                self._log.error("container_type={}".format(container_type))
                raise Exception("Container is not a case - {}".format(container_type))

            self._log.debug("container_info={}".format(json.dumps(container_info)))
            feed_id = self._feed_state.get("feed_id")
            report_hash = container_info.get("hash")
            report = None
            try:
                report = self.client.get_feed_report(feed_id, report_hash).get("report")
                self._log.debug("report={}".format(report))
            except Exception as e:
                self._log.warn("feed_id={} report_hash={} report_feed_error={}".format(feed_id, report_hash, e))
            if report is not None:
                iocsv2 = report.get("iocs_v2", [])

                def process_delete_ioc(self, ioc):
                    id_to_delete = param.get("iocid", "")
                    self._log.debug("action=using_ioc_id ioc_id={}".format(id_to_delete))
                    existing_ioc_id = ioc.get("id", "")
                    if existing_ioc_id == id_to_delete:
                        return None
                    return ioc
                if iocsv2 is None:
                    raise Exception("There is no iocsv2 value in feed report to delete")
                else:
                    new_iocs = [process_delete_ioc(self, ioc) for ioc in iocsv2]
                    report["iocs_v2"] = [ioc for ioc in new_iocs if ioc is not None]
                    report["timestamp"] = time.time()
                    self.client.update_feed_report(feed_id, report)
                    self.save_progress("Delete for IOCs: {} {}".format(feed_id, report))
                    self._log.debug(
                        "report={} param={}".format(json.dumps(report),
                                                    json.dumps(param)))
                    [action_result.add_data(x) for x in report.get("iocs_v2", [])]
                    return action_result.set_status(phantom.APP_SUCCESS, "Delete Report IOC Completed on feed: {}".format(feed_id))
            else:
                self.save_progress("Delete IOC: No Report Found")
                return action_result.set_status(phantom.APP_SUCCESS, "Delete IOC: No Report Found")

        except Exception as e:
            if "'NoneType' object has no attribute 'get'" in e.message:
                return action_result.set_status(phantom.APP_ERROR, "Found invalid org_key value in configuration parameters")
            self._log.error("Update Report IOC: {}".format(e))
            return action_result.set_status(phantom.APP_ERROR, "Error occured while deleting IOC from the report: {}".format(e))

    def _handle_update_report_ioc(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        exists, container_info, response_code = self.get_container_info()
        container_type = container_info.get("container_type", "default")

        ipv4 = param.get('ipv4_ioc')
        ipv6 = param.get('ipv6_ioc')
        domain = param.get('domain_ioc')
        hash = param.get('hash_ioc')

        if not (ipv4 or ipv6 or domain or hash):
            return action_result.set_status(phantom.APP_ERROR, "Atleast one parameter needs to be provided")
        if param.get('ipv4_ioc'):
            ret_val = self._is_ip(ipv4, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        if param.get('ipv6_ioc'):
            ret_val = self._is_ip(ipv6, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        try:
            if not container_type == "case":
                self._log.error("container_type={}".format(container_type))
                raise Exception("Container is not a case - {}".format(container_type))

            self._log.debug("container_info={}".format(json.dumps(container_info)))
            feed_id = self._feed_state.get("feed_id")
            report_hash = container_info.get("hash")
            report = None
            action = "update"
            try:
                report = self.client.get_feed_report(feed_id, report_hash).get("report")
                self._log.debug("report={}".format(report))
            except Exception as e:
                self._log.warn("feed_id={} report_hash={} report_feed_error={}".format(feed_id, report_hash, e))
            field_map = {"ipv4_ioc": "netconn_ipv4",
                         "ipv6_ioc": "netconn_ipv6",
                         "domain_ioc": "netconn_domain",
                         "hash_ioc": "hash"}
            reverse_field_map = {v: k for k, v in field_map.items()}

            def create_ioc(p):
                if p in field_map:
                    return {"values": [param.get(p, "")],
                            "id": "{}".format(uuid.uuid4()),
                            "field": field_map.get(p, "unknown"),
                            "match_type": "equality"}
                return None

            if report is None:
                severities = {"high": 1, "medium": 2, "low": 3}
                action = "add"

                iocs = [create_ioc(ioc) for ioc in param]
                report = {"id": report_hash,
                          # "timestamp": time.mktime(datetime.datetime.strptime("2019-03-14T13:24:52.991454Z",
                          #                                                    "%Y-%m-%dT%H:%M:%S.%fZ").timetuple()),
                          "timestamp": time.time(),
                          "title": "Case {} Report - {}".format(container_info.get("id"),
                                                                container_info.get("name", "no_name")),
                          "description": "{}".format(container_info.get("description", "No Description")),
                          "severity": severities.get(container_info.get("severity", "medium"), 1),
                          "tags": [container_info.get("label"), "phantom_created"],
                          "iocs_v2": [ioc for ioc in iocs if ioc is not None],
                          "visibility": "private"}
            else:
                action = "update"
                self._log.debug("action=found_report report={} action={} ".format(json.dumps(report), action))
                iocsv2 = report.get("iocs_v2", [])

                if iocsv2 is None:
                    iocsv2 = []

                existing_iocs = [x.get("field") for x in iocsv2]
                self._log.debug("action=checking_new_ioc existing_iocs={}".format(existing_iocs))
                [iocsv2.append(create_ioc(p)) for p in param if
                 field_map.get(p, "unknown") not in existing_iocs and p is not None]
                self._log.debug("action=checking_new_ioc updated_iocsv2={}".format(iocsv2))

                def process_update_ioc(self, ioc):
                    param_key = reverse_field_map.get(ioc.get("field", {}), "not_found")
                    self._log.debug("action=using_param_key param_key={} ioc_field={}".format(param_key,
                                                                                              ioc.get("field", {})))
                    # Check The IOC to see if it exists in the parameters sent from Phantom
                    if param.get(param_key) is not None:
                        self._log.debug("action=not_none_param_key param={} param_key={}".format(param.get(param_key),
                                                                                                 param_key))
                        # If it exists in the param AND the IOC, make sure param value in IOC
                        # ELSE ADD AS VALUE and return it
                        ioc_values = ioc.get("values", [])
                        if param.get(param_key) not in ioc_values:
                            self._log.debug("action=value_not_in_ioc_values values={} param_key={}".format(ioc_values,
                                                                                                           param_key))
                            # if the parameter is not in the ioc, append it to the list
                            ioc_values.append(param.get(param_key))
                            ioc["values"] = ioc_values
                        return ioc
                    else:
                        # If the PARAM was not passed, just return the IOC
                        self._log.debug("action=no_param_with_key param_key={}".format(param_key))
                        return ioc

                self._log.debug("iocsv2={} ".format(iocsv2))
                # This line updates *existing* iocs that map to the reverse_field_map
                report["iocs_v2"] = [process_update_ioc(self, ioc) for ioc in iocsv2 if ioc is not None]
            report["timestamp"] = time.time()
            self._log.debug(
                "action={} report={} param={} field_map={}".format(json.dumps(action), json.dumps(report),
                                                                   json.dumps(param),
                                                                   json.dumps(field_map)))
            r = self.client.update_feed_report(feed_id, report) if action == "update" else self.client.add_feed_report(
                feed_id, report)
            self.save_progress("Set Report for IOCs: {} {}".format(feed_id, report))
            [action_result.add_data(x) for x in report.get("iocs_v2", [])]
            self._log.debug("action=update_feed r={}".format(r))
            return action_result.set_status(phantom.APP_SUCCESS, "Update Feed Report Completed on feed ID: {}".format(feed_id))
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            if "'NoneType' object has no attribute 'get'" in e.message:
                return action_result.set_status(phantom.APP_ERROR, "Found invalid org_key value in configuration parameters")
            self._log.error("exception_line={} Update Report IOC: {}".format(exc_tb.tb_lineno, e))
            return action_result.set_status(phantom.APP_ERROR, "Error occured while updating the report: {}".format(e))

    def _process_iocs_v2(self, report):
        map_fields = {"netconn_ipv4": "ip",
                      "hash": "hash",
                      "netconn_domain": "domain",
                      "md5": "md5"}
        if report["iocs_v2"] is not None:
            report["indicators"] = [{"type": x["field"] if x["field"] not in map_fields else map_fields[x["field"]],
                                     "values": x["values"]} for x in
                                    report["iocs_v2"]]
            return report
        else:
            raise Exception("To get the report there is no ioc_v2 value for the requested feed")

    def _handle_get_feed_report(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            ret = self.client.get_feed_reports(param['feed_id'])
            self.save_progress("Getting feed reports for {}".format(param['feed_id']))
            self._log.info(
                "status=success feed={} length_reports={}".format(param['feed_id'], len(ret.get("results", []))))
            if ret.get("results") is not None:
                [action_result.add_data(self._process_iocs_v2(x)) for x in ret.get("results")]
            summary = action_result.update_summary({})
            summary['total_feed_reports'] = len(action_result.get_data())
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occured while getting feed report: {}".format(e))

    def _handle_delete_feed(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if "," in param['feed_id']:
            return action_result.set_status(phantom.APP_ERROR, "Comma separated values are not allowed.")
        try:
            ret = self.client.delete_feed(param['feed_id'])
            self.save_progress("Deleting feed for {}".format(param['feed_id']))
            self._log.info(
                "status=success feed={} ".format(param['feed_id']))
            [action_result.add_data(x) for x in ret.get("results", [])]
            return action_result.set_status(phantom.APP_SUCCESS, "Feed Deleted")
        except Exception as e:
            self._log.error("error={}".format(e))
            return action_result.set_status(phantom.APP_ERROR, "Error occured while deleting feed: {}".format(e))

    def _handle_get_single_feed(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if "," in param['feed_id']:
            return action_result.set_status(phantom.APP_ERROR, "Comma separated values are not allowed.")
        try:
            ret = self.client.get_feed(param['feed_id'])
            self.save_progress("Getting a feed {}".format(param['feed_id']))
            self._log.info("status=success length_feeds={}".format(ret.get("results", [])))
            action_result.add_data(ret.get("feedinfo", {}))
            return action_result.set_status(phantom.APP_SUCCESS, "Feed Retrieved")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occured while getting feed: {}".format(str(unicode(e.message).encode("utf-8"))))

    def _handle_get_all_feeds(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            self._log.info("params={}".format(param))
            ret = self.client.get_all_feeds(include_public=param.get("include_public", "false"))
            self.save_progress("Getting all feeds")
            self.save_progress("{}".format(json.dumps(ret)))
            self._log.info("status=success length_feeds={}".format(ret.get("results", [])))
            [action_result.add_data(x) for x in ret.get("results", [])]
            summary = action_result.update_summary({})
            summary['total_feeds'] = len(action_result.get_data())
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occured while getting feeds: {}".format(e))

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        self._log.debug("checking for connectivity")
        action_result = self.add_action_result(ActionResult(dict(param)))
        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Checking for connectivity")
        has_connectivity = self.client.has_connectivity(action_result)
        if phantom.is_fail(has_connectivity):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_file_to_vault(self, action_result, response, shash, file_summary, local_dir):
        zip_file_path = ('{0}/{1}.zip').format(local_dir, shash)
        with open(zip_file_path, 'wb') as (f):
            f.write(response.content)
        zf = zipfile.ZipFile(zip_file_path)
        try:
            zf.extractall(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'Unable to extract the zip file', e)

        file_path = ('{0}/filedata').format(local_dir)
        contains = []
        file_ext = ''
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if not file_ext:
                    file_ext = extension

        observed_filename = file_summary.get('original_filename')
        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=observed_filename,
                                              metadata={'contains': contains})
        curr_data = action_result.add_data({})
        curr_data["file_details"] = file_summary
        if vault_ret_dict['succeeded']:
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            curr_data[phantom.APP_JSON_NAME] = observed_filename
            wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
            summary = {x: curr_data[x] for x in wanted_keys}
            if contains:
                summary.update({'file_type': ','.join(contains)})
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])
        shutil.rmtree(local_dir)
        return action_result.get_status()

    def _handle_get_file(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        shash = param['file_hash_sha256']
        self.save_progress("Getting List of Files to Download")
        try:
            cb_response = self.client.get_file(shash=shash)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occured while getting file:", e)
            # return action_result.set_status(phantom.APP_ERROR, "Error occured while getting file: {}".format(str(unicode(e.message).encode("utf-8"))))
        if len(cb_response) < 1:
            return action_result.set_status(phantom.APP_SUCCESS, "No Files Found")
        self.save_progress("Found {} Files".format(len(cb_response)))
        guid = uuid.uuid4()
        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/vault/tmp'
        local_dir = temp_dir + ('/{}').format(guid)
        self.save_progress(('Using {0} directory: {1}').format(temp_dir, guid))
        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                            'Unable to create temporary folder {0}.'.format(temp_dir), e)
        [self._save_file_to_vault(action_result, x.get("response"), x.get("hash"), x.get("summary"), local_dir) for x
            in cb_response]
        return action_result.set_status(phantom.APP_SUCCESS, "File is Retrieved for Hash: {}".format(param['file_hash_sha256']))

    def _handle_get_file_metadata(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self._log.debug("starting action handler for {}".format(self.get_action_identifier()))
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        self._log.debug("action_result={}".format(action_result))
        file_hash = param['file_hash_sha256']
        reverse_map = {"sha256": "file_hash_sha256"}
        self.save_progress("Executing get file metadata on {}".format(file_hash))
        self._log.debug("action=execute_get_metadata sha256={}".format(file_hash))
        try:
            cbr = self.client.get_file_summary(file_hash)
            self._log.debug("action=call_complete ret={}".format(json.dumps(cbr)))
            self.save_progress("Completed call to client: {}".format(json.dumps(cbr)))
        except Exception as e:
            self.save_progress("Error on Get File Summary: {}".format(e))
            self._log.error("action=error error={}".format(e))
            return action_result.set_status(phantom.APP_ERROR, "{}".format("Get File Summary error: {}".format(e)))
        self._log.debug("adding data to action_result")
        if "error_code" in cbr:
            return RetVal(phantom.APP_ERROR, "{}: {}".format(cbr.get("error_code", "UNK"), cbr.get("message", "UNK")))
        action_result.add_data(self._process_row(cbr, reverse_map))
        self._log.debug("updating summary")
        summary = action_result.update_summary({})
        summary['total_objects'] = len(cbr.get("returned_data", []))
        summary['status'] = cbr.get("status", "unknown")
        return action_result.set_status(phantom.APP_SUCCESS, "File metadata is retrieved for the file hash: {}".format(param['file_hash_sha256']))

    def _handle_live_response(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self._log.debug("starting action handler for {}".format(self.get_action_identifier()))
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        field_map = {"ip": "netconn_ipv4",
                     "process_name": "process_name",
                     "domain": "netconn_domain",
                     "hash": "hash"}
        reverse_map = {v: k for k, v in field_map.items()}
        self.save_progress("Executing command {} on {}".format(param['command'], param['device_id']))
        self._log.debug("action=execute_command command={} device={}".format(param['command'], param['device_id']))
        try:
            self._log.debug(
                "action=call_live_response device={} command={} object={}".format(param['device_id'], param['command'],
                                                                                  param.get("object", "")))
            cbr = self.client.live_response(param['device_id'], param['command'], object=param.get("object", ""))
            self._log.debug("action=call_complete")
            self.save_progress("Completed call to client:  {}".format(json.dumps(cbr)))
        except Exception as e:
            if "object has no attribute 'status_code'" in "{}".format(e):
                self.save_progress("Error on Live Response command: Invalid URL, or Connection Failed{}".format(e))
                self._log.error("action=error type={} error={}".format(type(e), e))
                return action_result.set_status(phantom.APP_ERROR, "{}".format("Live Response error: {}".format(e)))
            else:
                self.save_progress("Error on Live Response command: {}".format(e))
                self._log.error("action=error type={} error={}".format(type(e), e))
                return action_result.set_status(phantom.APP_ERROR, "{}".format("Live Response error: {}".format(e)))
        self._log.debug("adding data to action_result")
        command = param.get("command")
        if command == "get file":
            data = {"File ID": cbr.get("returned_data", "")}
            [action_result.add_data(self._process_row(data, reverse_map))]
            return action_result.set_status(phantom.APP_SUCCESS, "File is retrived. File ID: {}".format(cbr.get("returned_data", "")))
        if command == "delete file":
            [action_result.add_data(self._process_row(x, reverse_map)) for x in cbr.get("returned_data", [])]
            summary = action_result.update_summary({})
            summary['total_objects'] = len(cbr.get("returned_data", []))
            summary['status'] = cbr.get("status", "unknown")
            return action_result.set_status(phantom.APP_SUCCESS, "File is deleted")
        if command == "process list":
            [action_result.add_data(self._process_row(x, reverse_map)) for x in cbr.get("returned_data", [])]
            summary = action_result.update_summary({})
            summary['total_objects'] = len(cbr.get("returned_data", []))
            summary['status'] = cbr.get("status", "unknown")
            return action_result.set_status(phantom.APP_SUCCESS, status_message=cbr.get("message"))
        if command == "kill":
            data = {"pid": cbr.get("returned_data", "")}
            [action_result.add_data(self._process_row(data, reverse_map))]
            return action_result.set_status(phantom.APP_SUCCESS, status_message=cbr.get("message"))

    def _handle_threat_feed(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_info = self.get_container_info()
        self._log.debug("container_info={}".format(container_info))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip = param.get("ip")
        if param.get('ip'):
            ret_val = self._is_ip(ip, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        # These are configured in the JSON, and set as allowed.
        valid_parameters = ["process_name", "hash", "ip", "domain"]
        # Field mapping is necessary to 'talk' between systems.

        field_map = {"ip": "netconn_ipv4",
                     "process_name": "process_name",
                     "domain": "netconn_domain",
                     "hash": "hash"}
        reverse_map = {v: k for k, v in field_map.items()}
        self.save_progress("Set mapping: {}".format(reverse_map))
        query = " {} ".format(param.get("search_operator", "AND")).join(
            ["{}:{}".format(field_map[k], v) for k, v in param.items() if k in valid_parameters and len(v) > 1])
        self.save_progress("Setting Query: {}".format(query))
        try:
            response = self.client.search_query(query, limit=param.get("max_results", 5000))
            if "failure" in response:
                return action_result.set_status(phantom.APP_ERROR, response.get("failure", ""))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occured while executing run query: {}".format(e))
        self.save_progress("Got a Valid Result of length: {}".format(len(response.get("success", {}))))
        # Add the response into the data section
        cb_response = response.get("success", {})
        [action_result.add_data(self._process_row(x, reverse_map)) for x in cb_response.get("data", [])]
        summary = action_result.update_summary({})
        summary['total_objects'] = len(cb_response.get("data", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _process_facet(self, v):
        # Combine the dictionary into a list of keys.
        return v.keys()

    def _process_row(self, row, rmap):
        # If any of the items in the row are lists, let's join them together in holy comma-ness.
        # return {k: v if not type(v) == list else ",".join([str(val) for val in v]) for k, v in row.items()}
        local_object = {k if k not in rmap else rmap[k]: v for k, v in row.items()}
        if type(local_object.get("process_hash", [])) == list and len(local_object.get("process_hash", [])) > 0:
            for h in local_object.get("process_hash"):
                if len(h) == 32:
                    local_object["process_hash_md5"] = h
                if len(h) == 64:
                    local_object["process_hash_sha256"] = h
        return local_object

    def _get_cb_feed(self):
        self._log.debug("action=get_feed directory={}".format(self._directory))
        touchpoint = os.path.join(self._directory, "phcarbonblackthreathunter_feed_state.json")
        static_feed = "{}".format(uuid.uuid5(uuid.NAMESPACE_OID, "Phantom"))
        if os.path.isfile(touchpoint):
            self._log.debug("action=get_feed file_exists={}".format(touchpoint))
            with open(touchpoint, "r") as f:
                self._feed_state = json.loads(f.readline())
            return None
        else:
            feeds = self.client.get_all_feeds()
            needed_category = "phantom_created"
            if not any([(x.get("category", "") == needed_category) for x in feeds.get("results", [])]):
                feed_information = self.client.create_feed(name="Phantom Created Threat Feed",
                                                           summary="Phantom Created and controlled threat feed",
                                                           access="private", category="phantom_created",
                                                           provider_url="https://my.phantom.us",
                                                           reports=[])
                self._log.debug(
                    "action=create_feed reason=none_present feed_information={}".format(json.dumps(feed_information)))
                static_feed = feed_information.get("id")
            else:
                for x in feeds.get("results"):
                    self._log.debug("checking_feed={} category={}".format(x.get("id"), x.get("category")))
                    if x.get("category", "") == needed_category:
                        static_feed = x.get("id")
                        break
            self._log.debug("action=no_path_to_touchpoint touchpoint={}".format(touchpoint))
            with open(touchpoint, "w") as f:
                f.write(json.dumps({"feed_id": static_feed}))
        self._log.debug("action=read_feed_state touchpoint={}".format(touchpoint))
        with open(touchpoint, "r") as f:
            self._feed_state = json.loads(f.readline())
        return None

    def _update_feed_state(self, key, value):
        self._feed_state[key] = value
        touchpoint = os.path.join(self._directory, "phcarbonblackthreathunter_feed_state.json")
        with open(touchpoint, "w") as f:
            f.write(json.dumps(self._feed_state))

    def handle_action(self, param):
        # Get the action that we are supposed to execute for this App Run
        self._log.debug("action=handle_action next=get_action_identifier")
        action_id = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS
        self._log.debug("action={}".format(self.get_action_identifier()))
        try:
            self._log.debug("action_function={}".format(self._action_functions[action_id]))
            ret_val = self._action_functions[action_id](param)
            return ret_val
        except Exception as e:
            return RetVal(phantom.APP_ERROR, "Action ID not found: {}, {}".format(action_id, e))

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._log.debug("starting load_state")
        self._state = self.load_state()
        self._log.debug("finished load_state")
        config = self.get_config()
        self._log.debug("finished get_config")
        aconfig = self.get_app_json()
        self._log.debug("finished get_app_json")
        if hasattr(Vault, 'get_vault_tmp_dir'):
            self._directory = Vault.get_vault_tmp_dir()
        else:
            self._directory = os.path.join(os.path.sep, "opt", "phantom", "apps", config.get("directory", ""))

        self.version = aconfig.get("app_version", "app_version_unknown")

        # self._log.debug("action=configs config={} aconfig={} state={}".format(json.dumps(config), json.dumps(aconfig),
        #                                                                     json.dumps(self._state)))
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """
        urls = ['base_url', 'api_url']
        for url in urls:
            if config[url]:
                if config[url][-1] == '/':
                    config[url] = config[url][:-1]
        config_params = ['base_url', 'api_id', 'org_key', 'lr_api_id', 'api_url']

        for config_param in config_params:
            if config.get(config_param) is not None:
                config[config_param] = config[config_param].encode('utf-8')

        self.client = cb_psc_client(base_url=config['base_url'],
                                    api_id=config["api_id"],
                                    api_secret_key=config["api_secret_key"],
                                    verify_ssl=config.get("verify_server_cert", False),
                                    version=self.version,
                                    org_key=config["org_key"],
                                    lr_api_secret_key=config.get("lr_api_secret_key", ""),
                                    lr_api_id=config.get("lr_api_id", ""),
                                    api_url=config.get("api_url", ""))
        app_config = aconfig.get("configuration", {})

        configuration_errors = self.apl_utils.validate_app_configuration(app_config, config)
        self.save_progress("Validating Asset Settings")
        if not any(configuration_errors):
            try:
                self._get_cb_feed()
            # If there are no errors, the list will be "all false", which when negated is "true", meaning no errors.
                return RetVal(phantom.APP_SUCCESS)
            except Exception as e:
                message = 'Error: {0}'.format(str(e))
                return RetVal(phantom.APP_ERROR, message)

        self.save_progress("{}".format(", ".join([x for x in configuration_errors if x])))
        return RetVal(phantom.APP_ERROR, "Failed Configuration Check")

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = CarbonBlackThreathunterConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CarbonBlackThreathunterConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
