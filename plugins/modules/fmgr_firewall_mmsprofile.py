#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_firewall_mmsprofile
short_description: Configure MMS profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    firewall_mmsprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            avnotificationtable:
                type: str
                description: AntiVirus notification table ID.
            bwordtable:
                type: str
                description: MMS banned word table ID.
            carrier_endpoint_prefix:
                type: str
                description: Enable/disable prefixing of end point values.
                choices:
                    - 'disable'
                    - 'enable'
            carrier_endpoint_prefix_range_max:
                type: int
                description: Maximum length of end point value that can be prefixed
            carrier_endpoint_prefix_range_min:
                type: int
                description: Minimum end point length to be prefixed
            carrier_endpoint_prefix_string:
                type: str
                description: String with which to prefix End point values.
            carrierendpointbwltable:
                type: str
                description: Carrier end point filter table ID.
            comment:
                type: str
                description: Comment.
            mm1:
                type: list
                elements: str
                description: MM1 options.
                choices:
                    - 'avmonitor'
                    - 'block'
                    - 'oversize'
                    - 'quarantine'
                    - 'scan'
                    - 'avquery'
                    - 'bannedword'
                    - 'no-content-summary'
                    - 'archive-summary'
                    - 'archive-full'
                    - 'carrier-endpoint-bwl'
                    - 'remove-blocked'
                    - 'chunkedbypass'
                    - 'clientcomfort'
                    - 'servercomfort'
                    - 'strict-file'
                    - 'mms-checksum'
            mm1_addr_hdr:
                type: str
                description: HTTP header field
            mm1_addr_source:
                type: str
                description: Source for MM1 user address.
                choices:
                    - 'http-header'
                    - 'cookie'
            mm1_convert_hex:
                type: str
                description: Enable/disable converting user address from HEX string for MM1.
                choices:
                    - 'disable'
                    - 'enable'
            mm1_outbreak_prevention:
                type: str
                description: Enable FortiGuard Virus Outbreak Prevention service.
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm1_retr_dupe:
                type: str
                description: Enable/disable duplicate scanning of MM1 retr.
                choices:
                    - 'disable'
                    - 'enable'
            mm1_retrieve_scan:
                type: str
                description: Enable/disable scanning on MM1 retrieve configuration messages.
                choices:
                    - 'disable'
                    - 'enable'
            mm1comfortamount:
                type: int
                description: MM1 comfort amount
            mm1comfortinterval:
                type: int
                description: MM1 comfort interval
            mm1oversizelimit:
                type: int
                description: Maximum file size to scan
            mm3:
                type: list
                elements: str
                description: MM3 options.
                choices:
                    - 'avmonitor'
                    - 'block'
                    - 'oversize'
                    - 'quarantine'
                    - 'scan'
                    - 'avquery'
                    - 'bannedword'
                    - 'no-content-summary'
                    - 'archive-summary'
                    - 'archive-full'
                    - 'carrier-endpoint-bwl'
                    - 'remove-blocked'
                    - 'fragmail'
                    - 'splice'
                    - 'mms-checksum'
            mm3_outbreak_prevention:
                type: str
                description: Enable FortiGuard Virus Outbreak Prevention service.
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm3oversizelimit:
                type: int
                description: Maximum file size to scan
            mm4:
                type: list
                elements: str
                description: MM4 options.
                choices:
                    - 'avmonitor'
                    - 'block'
                    - 'oversize'
                    - 'quarantine'
                    - 'scan'
                    - 'avquery'
                    - 'bannedword'
                    - 'no-content-summary'
                    - 'archive-summary'
                    - 'archive-full'
                    - 'carrier-endpoint-bwl'
                    - 'remove-blocked'
                    - 'fragmail'
                    - 'splice'
                    - 'mms-checksum'
            mm4_outbreak_prevention:
                type: str
                description: Enable FortiGuard Virus Outbreak Prevention service.
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm4oversizelimit:
                type: int
                description: Maximum file size to scan
            mm7:
                type: list
                elements: str
                description: MM7 options.
                choices:
                    - 'avmonitor'
                    - 'block'
                    - 'oversize'
                    - 'quarantine'
                    - 'scan'
                    - 'avquery'
                    - 'bannedword'
                    - 'no-content-summary'
                    - 'archive-summary'
                    - 'archive-full'
                    - 'carrier-endpoint-bwl'
                    - 'remove-blocked'
                    - 'chunkedbypass'
                    - 'clientcomfort'
                    - 'servercomfort'
                    - 'strict-file'
                    - 'mms-checksum'
            mm7_addr_hdr:
                type: str
                description: HTTP header field
            mm7_addr_source:
                type: str
                description: Source for MM7 user address.
                choices:
                    - 'http-header'
                    - 'cookie'
            mm7_convert_hex:
                type: str
                description: Enable/disable conversion of user address from HEX string for MM7.
                choices:
                    - 'disable'
                    - 'enable'
            mm7_outbreak_prevention:
                type: str
                description: Enable FortiGuard Virus Outbreak Prevention service.
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm7comfortamount:
                type: int
                description: MM7 comfort amount
            mm7comfortinterval:
                type: int
                description: MM7 comfort interval
            mm7oversizelimit:
                type: int
                description: Maximum file size to scan
            mms_antispam_mass_log:
                type: str
                description: Enable/disable logging for MMS antispam mass.
                choices:
                    - 'disable'
                    - 'enable'
            mms_av_block_log:
                type: str
                description: Enable/disable logging for MMS antivirus file blocking.
                choices:
                    - 'disable'
                    - 'enable'
            mms_av_oversize_log:
                type: str
                description: Enable/disable logging for MMS antivirus oversize file blocking.
                choices:
                    - 'disable'
                    - 'enable'
            mms_av_virus_log:
                type: str
                description: Enable/disable logging for MMS antivirus scanning.
                choices:
                    - 'disable'
                    - 'enable'
            mms_carrier_endpoint_filter_log:
                type: str
                description: Enable/disable logging for MMS end point filter blocking.
                choices:
                    - 'disable'
                    - 'enable'
            mms_checksum_log:
                type: str
                description: Enable/disable MMS content checksum logging.
                choices:
                    - 'disable'
                    - 'enable'
            mms_checksum_table:
                type: str
                description: MMS content checksum table ID.
            mms_notification_log:
                type: str
                description: Enable/disable logging for MMS notification messages.
                choices:
                    - 'disable'
                    - 'enable'
            mms_web_content_log:
                type: str
                description: Enable/disable logging for MMS web content blocking.
                choices:
                    - 'disable'
                    - 'enable'
            mmsbwordthreshold:
                type: int
                description: MMS banned word threshold.
            name:
                type: str
                description: Profile name.
                required: true
            notif_msisdn:
                type: list
                elements: dict
                description: Notif msisdn.
                suboptions:
                    msisdn:
                        type: str
                        description: Recipient MSISDN.
                    threshold:
                        type: list
                        elements: str
                        description: Thresholds on which this MSISDN will receive an alert.
                        choices:
                            - 'flood-thresh-1'
                            - 'flood-thresh-2'
                            - 'flood-thresh-3'
                            - 'dupe-thresh-1'
                            - 'dupe-thresh-2'
                            - 'dupe-thresh-3'
            remove_blocked_const_length:
                type: str
                description: Enable/disable MMS replacement of blocked file constant length.
                choices:
                    - 'disable'
                    - 'enable'
            replacemsg_group:
                type: str
                description: Replacement message group.
            dupe:
                type: dict
                description: Dupe.
                suboptions:
                    action1:
                        type: list
                        elements: str
                        description: Action to take when threshold reached.
                        choices:
                            - 'log'
                            - 'archive'
                            - 'intercept'
                            - 'block'
                            - 'archive-first'
                            - 'alert-notif'
                    action2:
                        type: list
                        elements: str
                        description: Action to take when threshold reached.
                        choices:
                            - 'log'
                            - 'archive'
                            - 'intercept'
                            - 'block'
                            - 'archive-first'
                            - 'alert-notif'
                    action3:
                        type: list
                        elements: str
                        description: Action to take when threshold reached.
                        choices:
                            - 'log'
                            - 'archive'
                            - 'intercept'
                            - 'block'
                            - 'archive-first'
                            - 'alert-notif'
                    block_time1:
                        type: int
                        description: Duration for which action takes effect
                    block_time2:
                        type: int
                        description: Duration for which action takes effect
                    block_time3:
                        type: int
                        description: Duration action takes effect
                    limit1:
                        type: int
                        description: Maximum number of messages allowed.
                    limit2:
                        type: int
                        description: Maximum number of messages allowed.
                    limit3:
                        type: int
                        description: Maximum number of messages allowed.
                    protocol:
                        type: str
                        description: Protocol.
                    status1:
                        type: str
                        description: Enable/disable status1 detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    status2:
                        type: str
                        description: Enable/disable status2 detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    status3:
                        type: str
                        description: Enable/disable status3 detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    window1:
                        type: int
                        description: Window to count messages over
                    window2:
                        type: int
                        description: Window to count messages over
                    window3:
                        type: int
                        description: Window to count messages over
            flood:
                type: dict
                description: Flood.
                suboptions:
                    action1:
                        type: list
                        elements: str
                        description: Action to take when threshold reached.
                        choices:
                            - 'log'
                            - 'archive'
                            - 'intercept'
                            - 'block'
                            - 'archive-first'
                            - 'alert-notif'
                    action2:
                        type: list
                        elements: str
                        description: Action to take when threshold reached.
                        choices:
                            - 'log'
                            - 'archive'
                            - 'intercept'
                            - 'block'
                            - 'archive-first'
                            - 'alert-notif'
                    action3:
                        type: list
                        elements: str
                        description: Action to take when threshold reached.
                        choices:
                            - 'log'
                            - 'archive'
                            - 'intercept'
                            - 'block'
                            - 'archive-first'
                            - 'alert-notif'
                    block_time1:
                        type: int
                        description: Duration for which action takes effect
                    block_time2:
                        type: int
                        description: Duration for which action takes effect
                    block_time3:
                        type: int
                        description: Duration action takes effect
                    limit1:
                        type: int
                        description: Maximum number of messages allowed.
                    limit2:
                        type: int
                        description: Maximum number of messages allowed.
                    limit3:
                        type: int
                        description: Maximum number of messages allowed.
                    protocol:
                        type: str
                        description: Protocol.
                    status1:
                        type: str
                        description: Enable/disable status1 detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    status2:
                        type: str
                        description: Enable/disable status2 detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    status3:
                        type: str
                        description: Enable/disable status3 detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    window1:
                        type: int
                        description: Window to count messages over
                    window2:
                        type: int
                        description: Window to count messages over
                    window3:
                        type: int
                        description: Window to count messages over
            notification:
                type: dict
                description: Notification.
                suboptions:
                    alert_int:
                        type: int
                        description: Alert notification send interval.
                    alert_int_mode:
                        type: str
                        description: Alert notification interval mode.
                        choices:
                            - 'hours'
                            - 'minutes'
                    alert_src_msisdn:
                        type: str
                        description: Specify from address for alert messages.
                    alert_status:
                        type: str
                        description: Alert notification status.
                        choices:
                            - 'disable'
                            - 'enable'
                    bword_int:
                        type: int
                        description: Banned word notification send interval.
                    bword_int_mode:
                        type: str
                        description: Banned word notification interval mode.
                        choices:
                            - 'hours'
                            - 'minutes'
                    bword_status:
                        type: str
                        description: Banned word notification status.
                        choices:
                            - 'disable'
                            - 'enable'
                    carrier_endpoint_bwl_int:
                        type: int
                        description: Carrier end point black/white list notification send interval.
                    carrier_endpoint_bwl_int_mode:
                        type: str
                        description: Carrier end point black/white list notification interval mode.
                        choices:
                            - 'hours'
                            - 'minutes'
                    carrier_endpoint_bwl_status:
                        type: str
                        description: Carrier end point black/white list notification status.
                        choices:
                            - 'disable'
                            - 'enable'
                    days_allowed:
                        type: list
                        elements: str
                        description: Weekdays on which notification messages may be sent.
                        choices:
                            - 'sunday'
                            - 'monday'
                            - 'tuesday'
                            - 'wednesday'
                            - 'thursday'
                            - 'friday'
                            - 'saturday'
                    detect_server:
                        type: str
                        description: Enable/disable automatic server address determination.
                        choices:
                            - 'disable'
                            - 'enable'
                    dupe_int:
                        type: int
                        description: Duplicate notification send interval.
                    dupe_int_mode:
                        type: str
                        description: Duplicate notification interval mode.
                        choices:
                            - 'hours'
                            - 'minutes'
                    dupe_status:
                        type: str
                        description: Duplicate notification status.
                        choices:
                            - 'disable'
                            - 'enable'
                    file_block_int:
                        type: int
                        description: File block notification send interval.
                    file_block_int_mode:
                        type: str
                        description: File block notification interval mode.
                        choices:
                            - 'hours'
                            - 'minutes'
                    file_block_status:
                        type: str
                        description: File block notification status.
                        choices:
                            - 'disable'
                            - 'enable'
                    flood_int:
                        type: int
                        description: Flood notification send interval.
                    flood_int_mode:
                        type: str
                        description: Flood notification interval mode.
                        choices:
                            - 'hours'
                            - 'minutes'
                    flood_status:
                        type: str
                        description: Flood notification status.
                        choices:
                            - 'disable'
                            - 'enable'
                    from_in_header:
                        type: str
                        description: Enable/disable insertion of from address in HTTP header.
                        choices:
                            - 'disable'
                            - 'enable'
                    mms_checksum_int:
                        type: int
                        description: MMS checksum notification send interval.
                    mms_checksum_int_mode:
                        type: str
                        description: MMS checksum notification interval mode.
                        choices:
                            - 'hours'
                            - 'minutes'
                    mms_checksum_status:
                        type: str
                        description: MMS checksum notification status.
                        choices:
                            - 'disable'
                            - 'enable'
                    mmsc_hostname:
                        type: str
                        description: Host name or IP address of the MMSC.
                    mmsc_password:
                        type: raw
                        description: (list) Password required for authentication with the MMSC.
                    mmsc_port:
                        type: int
                        description: Port used on the MMSC for sending MMS messages
                    mmsc_url:
                        type: str
                        description: URL used on the MMSC for sending MMS messages.
                    mmsc_username:
                        type: str
                        description: User name required for authentication with the MMSC.
                    msg_protocol:
                        type: str
                        description: Protocol to use for sending notification messages.
                        choices:
                            - 'mm1'
                            - 'mm3'
                            - 'mm4'
                            - 'mm7'
                    msg_type:
                        type: str
                        description: MM7 message type.
                        choices:
                            - 'submit-req'
                            - 'deliver-req'
                    protocol:
                        type: str
                        description: Protocol.
                    rate_limit:
                        type: int
                        description: Rate limit for sending notification messages
                    tod_window_duration:
                        type: str
                        description: Time of day window duration.
                    tod_window_end:
                        type: str
                        description: Obsolete.
                    tod_window_start:
                        type: str
                        description: Time of day window start.
                    user_domain:
                        type: str
                        description: Domain name to which the user addresses belong.
                    vas_id:
                        type: str
                        description: VAS identifier.
                    vasp_id:
                        type: str
                        description: VASP identifier.
                    virus_int:
                        type: int
                        description: Virus notification send interval.
                    virus_int_mode:
                        type: str
                        description: Virus notification interval mode.
                        choices:
                            - 'hours'
                            - 'minutes'
                    virus_status:
                        type: str
                        description: Virus notification status.
                        choices:
                            - 'disable'
                            - 'enable'
            outbreak_prevention:
                type: dict
                description: Outbreak prevention.
                suboptions:
                    external_blocklist:
                        type: str
                        description: Enable/disable external malware blocklist.
                        choices:
                            - 'disable'
                            - 'enable'
                    ftgd_service:
                        type: str
                        description: Enable/disable FortiGuard Virus outbreak prevention service.
                        choices:
                            - 'disable'
                            - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure MMS profiles.
      fortinet.fortimanager.fmgr_firewall_mmsprofile:
        bypass_validation: false
        adom: FortiCarrier # FortiCarrier only object, need a FortiCarrier adom
        state: present
        firewall_mmsprofile:
          comment: "ansible-comment"
          # extended-utm-log: disable
          mm1:
            - avmonitor
            - block
            - oversize
            - quarantine
            - scan
            - avquery
            - bannedword
            - no-content-summary
            - archive-summary
            - archive-full
            - carrier-endpoint-bwl
            - remove-blocked
            - chunkedbypass
            - clientcomfort
            - servercomfort
            - strict-file
            - mms-checksum
          mm3:
            - avmonitor
            - block
            - oversize
            - quarantine
            - scan
            - avquery
            - bannedword
            - no-content-summary
            - archive-summary
            - archive-full
            - carrier-endpoint-bwl
            - remove-blocked
            - fragmail
            - splice
            - mms-checksum
          mm4:
            - avmonitor
            - block
            - oversize
            - quarantine
            - scan
            - avquery
            - bannedword
            - no-content-summary
            - archive-summary
            - archive-full
            - carrier-endpoint-bwl
            - remove-blocked
            - fragmail
            - splice
            - mms-checksum
          mm7:
            - avmonitor
            - block
            - oversize
            - quarantine
            - scan
            - avquery
            - bannedword
            - no-content-summary
            - archive-summary
            - archive-full
            - carrier-endpoint-bwl
            - remove-blocked
            - chunkedbypass
            - clientcomfort
            - servercomfort
            - strict-file
            - mms-checksum
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the MMS profiles
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_mmsprofile"
          params:
            adom: "FortiCarrier" # FortiCarrier only object, need a FortiCarrier adom
            mms-profile: "your_value"
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/firewall/mms-profile',
        '/pm/config/global/obj/firewall/mms-profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'firewall_mmsprofile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'avnotificationtable': {'type': 'str'},
                'bwordtable': {'type': 'str'},
                'carrier-endpoint-prefix': {'choices': ['disable', 'enable'], 'type': 'str'},
                'carrier-endpoint-prefix-range-max': {'type': 'int'},
                'carrier-endpoint-prefix-range-min': {'type': 'int'},
                'carrier-endpoint-prefix-string': {'type': 'str'},
                'carrierendpointbwltable': {'type': 'str'},
                'comment': {'type': 'str'},
                'mm1': {
                    'type': 'list',
                    'choices': [
                        'avmonitor', 'block', 'oversize', 'quarantine', 'scan', 'avquery', 'bannedword', 'no-content-summary', 'archive-summary',
                        'archive-full', 'carrier-endpoint-bwl', 'remove-blocked', 'chunkedbypass', 'clientcomfort', 'servercomfort', 'strict-file',
                        'mms-checksum'
                    ],
                    'elements': 'str'
                },
                'mm1-addr-hdr': {'type': 'str'},
                'mm1-addr-source': {'choices': ['http-header', 'cookie'], 'type': 'str'},
                'mm1-convert-hex': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mm1-outbreak-prevention': {'choices': ['disabled', 'files', 'full-archive'], 'type': 'str'},
                'mm1-retr-dupe': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mm1-retrieve-scan': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mm1comfortamount': {'type': 'int'},
                'mm1comfortinterval': {'type': 'int'},
                'mm1oversizelimit': {'type': 'int'},
                'mm3': {
                    'type': 'list',
                    'choices': [
                        'avmonitor', 'block', 'oversize', 'quarantine', 'scan', 'avquery', 'bannedword', 'no-content-summary', 'archive-summary',
                        'archive-full', 'carrier-endpoint-bwl', 'remove-blocked', 'fragmail', 'splice', 'mms-checksum'
                    ],
                    'elements': 'str'
                },
                'mm3-outbreak-prevention': {'choices': ['disabled', 'files', 'full-archive'], 'type': 'str'},
                'mm3oversizelimit': {'type': 'int'},
                'mm4': {
                    'type': 'list',
                    'choices': [
                        'avmonitor', 'block', 'oversize', 'quarantine', 'scan', 'avquery', 'bannedword', 'no-content-summary', 'archive-summary',
                        'archive-full', 'carrier-endpoint-bwl', 'remove-blocked', 'fragmail', 'splice', 'mms-checksum'
                    ],
                    'elements': 'str'
                },
                'mm4-outbreak-prevention': {'choices': ['disabled', 'files', 'full-archive'], 'type': 'str'},
                'mm4oversizelimit': {'type': 'int'},
                'mm7': {
                    'type': 'list',
                    'choices': [
                        'avmonitor', 'block', 'oversize', 'quarantine', 'scan', 'avquery', 'bannedword', 'no-content-summary', 'archive-summary',
                        'archive-full', 'carrier-endpoint-bwl', 'remove-blocked', 'chunkedbypass', 'clientcomfort', 'servercomfort', 'strict-file',
                        'mms-checksum'
                    ],
                    'elements': 'str'
                },
                'mm7-addr-hdr': {'type': 'str'},
                'mm7-addr-source': {'choices': ['http-header', 'cookie'], 'type': 'str'},
                'mm7-convert-hex': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mm7-outbreak-prevention': {'choices': ['disabled', 'files', 'full-archive'], 'type': 'str'},
                'mm7comfortamount': {'type': 'int'},
                'mm7comfortinterval': {'type': 'int'},
                'mm7oversizelimit': {'type': 'int'},
                'mms-antispam-mass-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-av-block-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-av-oversize-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-av-virus-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-carrier-endpoint-filter-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-checksum-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-checksum-table': {'type': 'str'},
                'mms-notification-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-web-content-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mmsbwordthreshold': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'notif-msisdn': {
                    'type': 'list',
                    'options': {
                        'msisdn': {'type': 'str'},
                        'threshold': {
                            'type': 'list',
                            'choices': ['flood-thresh-1', 'flood-thresh-2', 'flood-thresh-3', 'dupe-thresh-1', 'dupe-thresh-2', 'dupe-thresh-3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'remove-blocked-const-length': {'choices': ['disable', 'enable'], 'type': 'str'},
                'replacemsg-group': {'type': 'str'},
                'dupe': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'action1': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                            'elements': 'str'
                        },
                        'action2': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                            'elements': 'str'
                        },
                        'action3': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                            'elements': 'str'
                        },
                        'block-time1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'block-time2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'block-time3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'limit1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'limit2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'limit3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'protocol': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'status1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'window1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'window2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'window3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}
                    }
                },
                'flood': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'action1': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                            'elements': 'str'
                        },
                        'action2': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                            'elements': 'str'
                        },
                        'action3': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                            'elements': 'str'
                        },
                        'block-time1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'block-time2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'block-time3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'limit1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'limit2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'limit3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'protocol': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'status1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'window1': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'window2': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'window3': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}
                    }
                },
                'notification': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'alert-int': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'alert-int-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                        'alert-src-msisdn': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'alert-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bword-int': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'bword-int-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                        'bword-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'carrier-endpoint-bwl-int': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'carrier-endpoint-bwl-int-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                        'carrier-endpoint-bwl-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'days-allowed': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                            'elements': 'str'
                        },
                        'detect-server': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dupe-int': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'dupe-int-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                        'dupe-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'file-block-int': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'file-block-int-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                        'file-block-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'flood-int': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'flood-int-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                        'flood-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'from-in-header': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mms-checksum-int': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mms-checksum-int-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                        'mms-checksum-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mmsc-hostname': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'mmsc-password': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'mmsc-port': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mmsc-url': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'mmsc-username': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'msg-protocol': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['mm1', 'mm3', 'mm4', 'mm7'], 'type': 'str'},
                        'msg-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['submit-req', 'deliver-req'], 'type': 'str'},
                        'protocol': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'rate-limit': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'tod-window-duration': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'tod-window-end': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.0']], 'type': 'str'},
                        'tod-window-start': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'user-domain': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'vas-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'vasp-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'virus-int': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'virus-int-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['hours', 'minutes'], 'type': 'str'},
                        'virus-status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'outbreak-prevention': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'external-blocklist': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ftgd-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_mmsprofile'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
