# File: cb_client.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
import phantom.app as phantom
import requests
from json import dumps
import time
from utilities import KennyLoggins, logging


class cb_psc_client:
    api_version = "v1"
    _session = requests.session()

    def __init__(self, **kwargs):
        self.base_url = kwargs["base_url"]
        self.api_url = kwargs["api_url"]
        self.version = kwargs["version"]
        self.org_key = kwargs["org_key"]
        self.authorization_header = "{1}/{0}".format(kwargs["api_id"], kwargs["api_secret_key"])
        self.live_header = "{}/{}".format(kwargs.get("lr_api_secret_key", ""), kwargs.get("lr_api_id", ""))
        self.user_agent_header = "Phantom App/{}".format(self.version)
        self._headers = {"User-Agent": self.user_agent_header,
                         "X-Auth-Token": self.authorization_header,
                         "Content-Type": "application/json"}
        self._live_headers = {"User-Agent": self.user_agent_header,
                              "X-Auth-Token": self.live_header,
                              "Content-Type": "application/json"}
        self._current_header = self._headers
        self.verify = kwargs["verify_ssl"]
        self._last_content = None
        kl = KennyLoggins()
        self._log = kl.get_logger(app_name="phcarbonblackthreathunter", file_name="cb_psc_client",
                                  log_level=logging.DEBUG, version=self.version)
        self._log.info("initialize_client=complete")

    def has_connectivity(self, action_result):
        try:
            self._log.debug("status=starting")
            endpoint = "threathunter/feedmgr/healthcheck"
            r = self.get(endpoint)
            if r.status_code == 204:
                self._last_content = ""
                return action_result.set_status(phantom.APP_SUCCESS, str(r.status_code))
            if r.status_code == 404:
                self._last_content = "404: URL {} not found".format(self._build_url(endpoint))
                return action_result.set_status(phantom.APP_ERROR, str(r.status_code))
            return action_result.set_status(phantom.APP_ERROR,
                        'Error occurred while running connectivity. The output response status code obtained is: {0}'.format(r.status_code))
        except Exception as e:
            self._log.debug("status=error {}".format(e))
            return action_result.set_status(phantom.APP_ERROR, str(e))

    def _build_url(self, endpoint):
        if "integrationServices" in endpoint:
            self._current_header = self._live_headers
            return self._build_live_url(endpoint)
        self._current_header = self._headers
        self._log.debug("action=build_url url={} endpoint={}".format(self.base_url, endpoint))
        return "{}/{}".format(self.base_url, endpoint)

    def _build_live_url(self, endpoint):
        self._log.debug("action=build_live_url url={} endpoint={}".format(self.api_url, endpoint))
        return "{}/{}".format(self.api_url, endpoint)

    def last_content(self):
        return self._last_content

    def put(self, endpoint, **kwargs):
        url = self._build_url(endpoint)
        self._log.debug("status=start url={}".format(url))
        try:
            r = self._session.put(
                url,
                verify=self.verify,
                headers=self._current_header,
                **kwargs
            )
            self._last_content = "{}: {}: {}".format(url, r.status_code, r.text)
            return r
        except Exception as e:
            raise e

    def get(self, endpoint, **kwargs):
        url = self._build_url(endpoint)
        self._log.debug("status=start url={}".format(url))
        try:
            r = self._session.get(
                url,
                verify=self.verify,
                headers=self._current_header,
                **kwargs
            )
            self._last_content = "{}: {}: {}".format(url, r.status_code, r.text.encode('utf-8'))
            return r
        except Exception as e:
            # raise Exception("Error: {} {}".format(unicode(str(e.message)).encode("utf-8"), self._last_content))
            raise Exception("Error occured while getting the response from URL, may be it is an invalid URL {}".format(unicode(str(e.message))))
            # raise Exception(unicode(str(e.message)).encode("utf-8"))

    def delete(self, endpoint):
        url = self._build_url(endpoint)
        self._log.debug("status=start url={}".format(url))
        r = self._session.delete(
            url,
            verify=self.verify,
            headers=self._current_header
        )
        self._last_content = "{}: {}: {}".format(url, r.status_code, r.text.encode('utf-8'))
        return r

    def external_get(self, url, **kwargs):
        if url is None:
            return {}
        self._log.debug("status=start url={}".format(url))
        tmp_session = requests.session()
        return tmp_session.get(url,
                               **kwargs)

    def post(self, endpoint, data={}, **kwargs):
        url = self._build_url(endpoint)
        self._log.debug("status=start url={}".format(url))
        r = None
        try:
            r = self._session.post(
                url,
                data=data,
                headers=self._current_header,
                json=True,
                **kwargs
            )
            self._log.debug(
                "status=end url={} code={} content={} headers={}".format(url, r.status_code, r.content, r.headers))
            return r
        except Exception as e:
            raise Exception(e)
            # self._log.debug("action=exception method=post url={} e=\"{}\"".format(url, e))
            # raise Exception("Error occured while getting the response from URL, may be it is an invalid URL")
            # self._log.error("Post Exception: {} {}".format(r.status_code, r.text))
            # raise Exception(unicode(str(e.message)).encode("utf-8"))

    def get_file_summary(self, shash):
        endpoint = "ubs/{}/orgs/{}/sha256/{}/metadata".format(self.api_version, self.org_key, shash)
        self._log.debug("status=start endpoint={}".format(endpoint))
        return self.get(endpoint).json()

    def get_file(self, shash=None):
        self._last_content = "action=get_file_init hash={}".format(shash)
        if shash is None or self.org_key is None:
            raise Exception("Hash not passed")
        endpoint = "ubs/{}/orgs/{}/file/_download".format(self.api_version, self.org_key)
        self._last_content = "hitting endpoint {}".format(endpoint)
        d = {"sha256": [shash], "expiration_seconds": 60}
        try:
            r = self.post(endpoint, data=dumps(d))
            try:
                resp = r.json()
            except:
                raise Exception("Response data is not in json format, got error {}".format(r.status_code))

            self._last_content = "endpoint response: {}: {}".format(r.status_code, r.text.encode('utf-8'))
            if "error_code" in r.json():
                resp = r.json()
                raise Exception("{} - {}: {}   DEBUG: url:{}, d:{}".format(r.status_code, resp.get("error_code"),
                                                                        resp.get("message"), endpoint, dumps(resp)))

            retrieved_responses = []
            if "found" in r.json():
                resp = r.json()
                self._last_content = "Found {} hashes".format(len(resp.get("found", [])))
                retrieved_responses = [{"response": self.external_get(x.get("url")), "hash": x.get("sha256"),
                                        "summary": self.get_file_summary(x.get("sha256"))} for x in
                                    resp.get("found", [])]

            self._last_content = "Retrieved {} hashes".format(len(retrieved_responses))
            return retrieved_responses
        except Exception as e:
            raise Exception(e)

    def _search_start(self, query, limit=5000):
        # process_cmdline : Does Not Support Facet
        # process_username: Does Not Support Facet
        # hash: Does Not Support Facet
        data = {"search_params": {"q": query,
                                  "facet.field": ["process_name", "device_name", "process_username",
                                                  "netconn_ipv4", "process_hash"],
                                  "rows": limit,
                                  "facet": True,
                                  "facet.mincount": 1,
                                  "sort": "device_timestamp desc"
                                  }}
        endpoint = "pscr/query/{}/start".format(self.api_version)
        r = self.post(endpoint, data=dumps(data))
        resp = r.json()
        if "error_code" in resp:
            raise Exception("{} - {}: {}   DEBUG: url:{}, d:{}".format(r.status_code, resp.get("error_code"),
                                                                       resp.get("message"), endpoint, dumps(resp)))
        return {"success": resp.get("query_id")}

    def _search_cancel(self, guid=""):
        endpoint = "pscr/query/{}/cancel".format(self.api_version)
        r = self.post(endpoint, data=dumps({"query_id": guid}))
        resp = r.json()
        if "error_code" in resp:
            raise Exception("{} - {}: {}   DEBUG: url:{}, d:{}".format(r.status_code, resp.get("error_code"),
                                                                       resp.get("message"), endpoint, dumps(resp)))
        return {"success": resp.get("query_id")}

    def _search_status(self, block=False, step=0, guid="", max_loops=5):
        current_loop = 0
        endpoint = "pscr/query/{}/results".format(self.api_version)
        r = self.post(endpoint, data=dumps({"query_id": guid}))
        if r.status_code == 200:
            return {"success": r.json()}
        failed = False
        while block:
            current_loop = current_loop + 1
            time.sleep(step)
            r = self.post(endpoint, data=dumps({"query_id": guid}))
            if r.status_code == 200:
                block = False
            if current_loop >= max_loops:
                block = False
                failed = True
                self._search_cancel(guid=guid)
        if failed:
            raise Exception("{} - {}: DEBUG: url:{}, d:{}".format(r.status_code, r.status_code, endpoint,
                                                                  dumps(r.json())))
        return {"success": r.json()}

    def search_query(self, query, limit=5000):
        query_start = self._search_start(query, limit=limit)
        if "failure" in query_start:
            return query_start
        return self._search_status(block=True, step=5, guid=query_start.get("success"))

    # ### Live Response Helpers

    def _live_response_process(self, response, msg=""):
        self._log.debug("status=trace response={}".format(response))
        self._log.debug("status=start code={}".format(response.status_code))
        if response.status_code == 200:
            return response.json()
        self._log.debug("status=failed code={} text={}".format(response.status_code, response))
        ret_j = response.json()
        self._log.debug(
            "status=response_received status={} {}".format(response.status_code,
                                                           " ".join(["{}=\"{}\"".format(x, ret_j.get(x, "")) for x in
                                                                     ret_j])))
        raise Exception("{}: status_code={} text={}".format(msg, response.status_code, response.text))

    def _build_live_endpoint(self, endpoint):
        return "integrationServices/v3/cblr/session{}".format(endpoint)

    def _open_live_session(self, device_id):
        endpoint = self._build_live_endpoint("/{}".format(device_id))
        self._log.debug("status=start endpoint={}".format(endpoint))
        return self._live_response_process(self.post(endpoint, data=dumps({"sensor_id": device_id})),
                                           msg="Live Response Session Failed to Open")

    def _check_live_session(self, session_id):
        endpoint = "integrationServices/v3/cblr/session/{}".format(session_id)
        self._log.debug("status=start endpoint={}".format(endpoint))
        return self._live_response_process(self.get(endpoint), msg="Failure on Check Live Response Session")

    def _issue_live_command(self, session_id, command, **kwargs):
        endpoint = "integrationServices/v3/cblr/session/{}/command".format(session_id)
        self._log.debug("status=start endpoint={}".format(endpoint))
        data = {"session_id": session_id, "name": command}
        # ps: name, object
        # kill: name, object
        # delete file: name, object
        # get file: name, object (SECOND API REQUIRED)
        if command in ["kill", "delete file", "get file"]:
            data["object"] = kwargs.get("object", {})
        else:
            data["object"] = ""
        # self._log.debug("status=start to_call=_live_response_process_command endpoint={} data={} headers={}".format(endpoint, dumps(data), self._current_header))
        return self._live_response_process(self.post(endpoint, data=dumps(data)),
                                           msg="Failure on Live Response Command Issue")

    def _check_live_session_command(self, session_id):
        endpoint = "integrationServices/v3/cblr/session/{}/command/0".format(session_id)
        self._log.debug("status=start endpoint={}".format(endpoint))
        return self._live_response_process(self.get(endpoint), msg="Failure on Check Live Response Command")

    def _get_file_content(self, session_id, file_id):
        endpoint = "integrationServices/v3/cblr/session/{}/file/{}/content".format(session_id, file_id)
        self._log.debug("status=start endpoint={}".format(endpoint))
        return self._live_response_process(self.get(endpoint), msg="Failure on Get File Contents")

    def _close_session(self, session_id):
        endpoint = "integrationServices/v3/cblr/session"
        self._log.debug("status=start endpoint={}".format(endpoint))
        data = {"session_id": session_id, "status": "CLOSE"}
        return self._live_response_process(self.put(endpoint, data=dumps(data)), msg="Failure on Close Session")

    def _process_json(self, j):
        return " ".join(["{}=\"{}\"".format(x, j.get(x, "")) for x in j])

    def live_response(self, device_id, command, **kwargs):
        # Local 'Globals'
        self._log.debug("status=start")
        # if len(self.api_url) < 1:
        if not self.api_url:
            raise Exception("No Live Response API provided.")
        max_wait_loops = 10
        wait_time = 5
        map_responses = {"process list": "processes", "get file": "file_id"}
        # Open Season
        self._log.debug("action=start to_call=_open_live_session")
        try:
            open_session = self._open_live_session(device_id)
        except Exception as e:
            raise Exception(e)
        self._log.debug("action=end to_call=_open_live_session {}".format(self._process_json(open_session)))
        counter = 0
        session_id = open_session.get("id")
        if session_id is None:
            self._log.error("Failed to get sessionID")
            raise Exception("Failed to Get SessionID")
        # Ready Player 1
        while counter < max_wait_loops:
            self._log.debug("action=start to_call=_check_live_session max_wait_loops={} counter={} wait_time={}".format(
                max_wait_loops, counter, wait_time))
            time.sleep(wait_time)
            get_check = self._check_live_session(session_id)
            self._log.debug("action=end to_call=_check_live_session {}".format(self._process_json(get_check)))
            if get_check.get("status") == "ACTIVE":
                self._log.debug("action=break")
                break
            else:
                self._log.debug("action=continue")
                counter = counter + 1
        # Issue Command
        if counter == max_wait_loops:
            self._log.error(
                "action=exception counter=max_wait_loops counter={} max_wait_loops={}".format(counter, max_wait_loops))
            try:
                self._close_session(session_id)
            except:
                pass
            raise Exception("Max Loops of {} exceeded for Session Check {}".format(max_wait_loops, session_id))
        counter = 0
        self._log.debug("action=start to_call=_issue_live_command kwargs={}".format(kwargs))
        ic = self._issue_live_command(session_id, command, **kwargs)
        self._log.debug("action=end to_call=_issue_live_command {}".format(self._process_json(ic)))
        # Ready Player 2
        ret_val = None
        while counter < max_wait_loops:
            self._log.debug(
                "action=start to_call=_check_live_session_command max_wait_loops={} counter={} wait_time={}".format(
                    max_wait_loops, counter, wait_time
                ))
            time.sleep(wait_time)
            get_check = self._check_live_session_command(session_id)
            self._log.debug("action=end to_call=_check_live_session_command")
            if get_check.get("status") == "complete":
                self._log.debug("action=break")
                ret_val = get_check
                break
            else:
                self._log.debug("action=continue")
                counter = counter + 1
        if counter == max_wait_loops:
            self._log.error(
                "action=exception counter=max_wait_loops counter={} max_wait_loops={}".format(counter, max_wait_loops))
            try:
                self._close_session(session_id)
            except:
                pass
            raise Exception("Max Loops of {} exceed for Command Check {}".format(max_wait_loops, session_id))
        if command in map_responses.keys():
            # Get the Response, and map to a generic return object 'returned_data'
            ret_val["returned_data"] = ret_val.get(map_responses.get(command))
            self._log.debug("status=found_map command={}".format(command))
        try:
            self._close_session(session_id)
        except:
            pass
        return ret_val

    # Feed Actions
    def _build_feed_url(self, endpoint=""):
        return "threathunter/feedmgr/{}/orgs/{}/feeds{}".format("v2", self.org_key, endpoint)

    def _feed_process(self, response):
        if "status_code" in response:
            self._log.debug("action=got_response status={} text={}".format(response.status_code, response.text.encode('utf-8')))
        if not isinstance(response, str):
            if response.status_code == 200:
                return response.json()
            if response.status_code == 204:
                return {}
        raise Exception("Error on Call: status_code={} text={}".format(response.status_code, response.text.encode('utf-8')))

    def create_feed(self, name="", owner="", summary="", access="private",
                    reports=[], **kwargs):
        data = {"feedinfo": {"name": name,
                             "owner": owner,
                             "provider_url": kwargs.get("provider_url", ""),
                             "summary": summary,
                             "category": kwargs.get("category", "unknown"),
                             "access": access,
                             "id": kwargs.get("id", None)},
                "reports": reports}
        if access == "public":
            return self._create_public_feed(data)
        else:
            return self._create_private_feed(data)

    def _create_private_feed(self, data):
        try:
            return self._feed_process(self.post(self._build_feed_url(), data=dumps(data)))
        except Exception as e:
            raise Exception(e)

    def _create_public_feed(self, data):
        try:
            return self._feed_process(self.post(self._build_feed_url("/public"), data=dumps(data)))
        except Exception as e:
            raise Exception(e)

    def get_all_feeds(self, include_public="false"):
        try:
            return self._feed_process(self.get("{}?include_public={}".format(self._build_feed_url(), include_public)))
        except Exception as e:
            raise Exception(e)

    def get_feed(self, feed_id):
        try:
            return self._feed_process(self.get(self._build_feed_url("/{}".format(feed_id))))
        except Exception as e:
            raise Exception(e)

    def delete_feed(self, feed_id):
        try:
            return self._feed_process(self.delete(self._build_feed_url("/{}".format(feed_id))))
        except Exception as e:
            raise Exception(e)

    def get_feed_info(self, feed_id):
        try:
            return self._feed_process(self.get(self._build_feed_url("/{}/feedinfo".format(feed_id))))
        except Exception as e:
            raise Exception(e)

    # Update Feed Info
    def update_feed_info(self, feed_id, meta):
        try:
            return self._feed_process(self.put(self._build_feed_url("/{}/feedinfo".format(feed_id)), data=dumps(meta)))
        except Exception as e:
            raise Exception(e)

    # Get Threat Reports
    def get_feed_reports(self, feed_id):
        try:
            return self._feed_process(self.get(self._build_feed_url("/{}/reports".format(feed_id))))
        except Exception as e:
            raise Exception(e)

    def replace_feed_reports(self, feed_id, reports):
        try:
            return self._feed_process(self.post(self._build_feed_url("/{}/reports".format(feed_id)), data=dumps(reports)))
        except Exception as e:
            raise Exception(e)

    def add_feed_report(self, feed_id, report):
        reports = self.get_feed_reports(feed_id).get("results")
        reports.append(report)
        try:
            return self.replace_feed_reports(feed_id, {"reports": reports})
        except Exception as e:
            raise Exception(e)
    # Get Specific Report

    def get_feed_report(self, feed_id, report_id):
        try:
            return self._feed_process(self.get(self._build_feed_url("/{}/reports/{}".format(feed_id, report_id))))
        except Exception as e:
            raise Exception(e)

    def add_indicator(self, feed_id, indicator=None, report_id=None):
        report = None
        if report_id is None:
            reports = self.get_feed_reports(feed_id)
            if len(reports) > 0:
                report = reports[0]
        # Run update if a report is found
        if report is None:
            raise Exception("No Report Found")
        if "iocs_v2" not in report:
            report["iocs_v2"] = []
        report["iocs_v2"].append(indicator)
        # If report id is None, check for existing Report
        # if report_id is None: reports = len(self.get_feed_reports(feed_id).get("results", []))
        # if len_reports > 0: Choose first, get report_id
        # Add the indicator to the report
        # self.update_feed_report(feed_id, report_id, report)
        return self.update_feed_report(feed_id, report)

    # Update Report
    def update_feed_report(self, feed_id, report):
        self._log.debug("updating_report={} feed={}".format(dumps(report), feed_id))
        return self._feed_process(
            self.put(self._build_feed_url("/{}/reports/{}".format(feed_id, report["id"])), data=dumps(report)))
