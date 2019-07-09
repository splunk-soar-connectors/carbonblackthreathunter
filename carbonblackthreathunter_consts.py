# File: carbonblackthreathunter_consts.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.# Define your constants here

# Threat Feed Defaults
THREAT_FEED_TITLE = ""
CBTHREATHUNTER_GET_CB_FEED_ERROR = 'Error occurred while getting the required Feed ID: {error_msg}. Please delete the file: {file_path} and try again'
CBTHREATHUNTER_DELETE_IOC_VALUES_EMPTY = 'There are no IOC values to be deleted in the feed report ID: {report_id} for the feed ID: {feed_id}'
CBTHREATHUNTER_DELETE_IOC_ID_INVALID = 'The IOC ID: {ioc_id} is either invalid or already deleted for the feed report ID: {report_id} of the feed ID: {feed_id}'
