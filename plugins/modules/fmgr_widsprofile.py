#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_widsprofile
short_description: Configure wireless intrusion detection system (WIDS) profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    widsprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            ap-auto-suppress:
                type: str
                description: 'Enable/disable on-wire rogue AP auto-suppression (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            ap-bgscan-disable-day:
                description: no description
                type: list
                choices:
                 - sunday
                 - monday
                 - tuesday
                 - wednesday
                 - thursday
                 - friday
                 - saturday
            ap-bgscan-disable-end:
                type: str
                description: 'End time, using a 24-hour clock in the format of hh:mm, for disabling background scanning (default = 00:00).'
            ap-bgscan-disable-start:
                type: str
                description: 'Start time, using a 24-hour clock in the format of hh:mm, for disabling background scanning (default = 00:00).'
            ap-bgscan-duration:
                type: int
                description: 'Listening time on a scanning channel (10 - 1000 msec, default = 20).'
            ap-bgscan-idle:
                type: int
                description: 'Waiting time for channel inactivity before scanning this channel (0 - 1000 msec, default = 0).'
            ap-bgscan-intv:
                type: int
                description: 'Period of time between scanning two channels (1 - 600 sec, default = 1).'
            ap-bgscan-period:
                type: int
                description: 'Period of time between background scans (60 - 3600 sec, default = 600).'
            ap-bgscan-report-intv:
                type: int
                description: 'Period of time between background scan reports (15 - 600 sec, default = 30).'
            ap-fgscan-report-intv:
                type: int
                description: 'Period of time between foreground scan reports (15 - 600 sec, default = 15).'
            ap-scan:
                type: str
                description: 'Enable/disable rogue AP detection.'
                choices:
                    - 'disable'
                    - 'enable'
            ap-scan-passive:
                type: str
                description: 'Enable/disable passive scanning. Enable means do not send probe request on any channels (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            asleap-attack:
                type: str
                description: 'Enable/disable asleap attack detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            assoc-flood-thresh:
                type: int
                description: 'The threshold value for association frame flooding.'
            assoc-flood-time:
                type: int
                description: 'Number of seconds after which a station is considered not connected.'
            assoc-frame-flood:
                type: str
                description: 'Enable/disable association frame flooding detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            auth-flood-thresh:
                type: int
                description: 'The threshold value for authentication frame flooding.'
            auth-flood-time:
                type: int
                description: 'Number of seconds after which a station is considered not connected.'
            auth-frame-flood:
                type: str
                description: 'Enable/disable authentication frame flooding detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: 'Comment.'
            deauth-broadcast:
                type: str
                description: 'Enable/disable broadcasting de-authentication detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            deauth-unknown-src-thresh:
                type: int
                description: 'Threshold value per second to deauth unknown src for DoS attack (0: no limit).'
            eapol-fail-flood:
                type: str
                description: 'Enable/disable EAPOL-Failure flooding (to AP) detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            eapol-fail-intv:
                type: int
                description: 'The detection interval for EAPOL-Failure flooding (1 - 3600 sec).'
            eapol-fail-thresh:
                type: int
                description: 'The threshold value for EAPOL-Failure flooding in specified interval.'
            eapol-logoff-flood:
                type: str
                description: 'Enable/disable EAPOL-Logoff flooding (to AP) detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            eapol-logoff-intv:
                type: int
                description: 'The detection interval for EAPOL-Logoff flooding (1 - 3600 sec).'
            eapol-logoff-thresh:
                type: int
                description: 'The threshold value for EAPOL-Logoff flooding in specified interval.'
            eapol-pre-fail-flood:
                type: str
                description: 'Enable/disable premature EAPOL-Failure flooding (to STA) detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            eapol-pre-fail-intv:
                type: int
                description: 'The detection interval for premature EAPOL-Failure flooding (1 - 3600 sec).'
            eapol-pre-fail-thresh:
                type: int
                description: 'The threshold value for premature EAPOL-Failure flooding in specified interval.'
            eapol-pre-succ-flood:
                type: str
                description: 'Enable/disable premature EAPOL-Success flooding (to STA) detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            eapol-pre-succ-intv:
                type: int
                description: 'The detection interval for premature EAPOL-Success flooding (1 - 3600 sec).'
            eapol-pre-succ-thresh:
                type: int
                description: 'The threshold value for premature EAPOL-Success flooding in specified interval.'
            eapol-start-flood:
                type: str
                description: 'Enable/disable EAPOL-Start flooding (to AP) detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            eapol-start-intv:
                type: int
                description: 'The detection interval for EAPOL-Start flooding (1 - 3600 sec).'
            eapol-start-thresh:
                type: int
                description: 'The threshold value for EAPOL-Start flooding in specified interval.'
            eapol-succ-flood:
                type: str
                description: 'Enable/disable EAPOL-Success flooding (to AP) detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            eapol-succ-intv:
                type: int
                description: 'The detection interval for EAPOL-Success flooding (1 - 3600 sec).'
            eapol-succ-thresh:
                type: int
                description: 'The threshold value for EAPOL-Success flooding in specified interval.'
            invalid-mac-oui:
                type: str
                description: 'Enable/disable invalid MAC OUI detection.'
                choices:
                    - 'disable'
                    - 'enable'
            long-duration-attack:
                type: str
                description: 'Enable/disable long duration attack detection based on user configured threshold (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            long-duration-thresh:
                type: int
                description: 'Threshold value for long duration attack detection (1000 - 32767 usec, default = 8200).'
            name:
                type: str
                description: 'WIDS profile name.'
            null-ssid-probe-resp:
                type: str
                description: 'Enable/disable null SSID probe response detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            sensor-mode:
                type: str
                description: 'Scan WiFi nearby stations (default = disable).'
                choices:
                    - 'disable'
                    - 'foreign'
                    - 'both'
            spoofed-deauth:
                type: str
                description: 'Enable/disable spoofed de-authentication attack detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            weak-wep-iv:
                type: str
                description: 'Enable/disable weak WEP IV (Initialization Vector) detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            wireless-bridge:
                type: str
                description: 'Enable/disable wireless bridge detection (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure wireless intrusion detection system (WIDS) profiles.
      fmgr_widsprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         widsprofile:
            ap-auto-suppress: <value in [disable, enable]>
            ap-bgscan-disable-day:
              - sunday
              - monday
              - tuesday
              - wednesday
              - thursday
              - friday
              - saturday
            ap-bgscan-disable-end: <value of string>
            ap-bgscan-disable-start: <value of string>
            ap-bgscan-duration: <value of integer>
            ap-bgscan-idle: <value of integer>
            ap-bgscan-intv: <value of integer>
            ap-bgscan-period: <value of integer>
            ap-bgscan-report-intv: <value of integer>
            ap-fgscan-report-intv: <value of integer>
            ap-scan: <value in [disable, enable]>
            ap-scan-passive: <value in [disable, enable]>
            asleap-attack: <value in [disable, enable]>
            assoc-flood-thresh: <value of integer>
            assoc-flood-time: <value of integer>
            assoc-frame-flood: <value in [disable, enable]>
            auth-flood-thresh: <value of integer>
            auth-flood-time: <value of integer>
            auth-frame-flood: <value in [disable, enable]>
            comment: <value of string>
            deauth-broadcast: <value in [disable, enable]>
            deauth-unknown-src-thresh: <value of integer>
            eapol-fail-flood: <value in [disable, enable]>
            eapol-fail-intv: <value of integer>
            eapol-fail-thresh: <value of integer>
            eapol-logoff-flood: <value in [disable, enable]>
            eapol-logoff-intv: <value of integer>
            eapol-logoff-thresh: <value of integer>
            eapol-pre-fail-flood: <value in [disable, enable]>
            eapol-pre-fail-intv: <value of integer>
            eapol-pre-fail-thresh: <value of integer>
            eapol-pre-succ-flood: <value in [disable, enable]>
            eapol-pre-succ-intv: <value of integer>
            eapol-pre-succ-thresh: <value of integer>
            eapol-start-flood: <value in [disable, enable]>
            eapol-start-intv: <value of integer>
            eapol-start-thresh: <value of integer>
            eapol-succ-flood: <value in [disable, enable]>
            eapol-succ-intv: <value of integer>
            eapol-succ-thresh: <value of integer>
            invalid-mac-oui: <value in [disable, enable]>
            long-duration-attack: <value in [disable, enable]>
            long-duration-thresh: <value of integer>
            name: <value of string>
            null-ssid-probe-resp: <value in [disable, enable]>
            sensor-mode: <value in [disable, foreign, both]>
            spoofed-deauth: <value in [disable, enable]>
            weak-wep-iv: <value in [disable, enable]>
            wireless-bridge: <value in [disable, enable]>

'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile',
        '/pm/config/global/obj/wireless-controller/wids-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile/{wids-profile}',
        '/pm/config/global/obj/wireless-controller/wids-profile/{wids-profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'widsprofile': {
            'required': False,
            'type': 'dict',
            'options': {
                'ap-auto-suppress': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-bgscan-disable-day': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'sunday',
                        'monday',
                        'tuesday',
                        'wednesday',
                        'thursday',
                        'friday',
                        'saturday'
                    ]
                },
                'ap-bgscan-disable-end': {
                    'required': False,
                    'type': 'str'
                },
                'ap-bgscan-disable-start': {
                    'required': False,
                    'type': 'str'
                },
                'ap-bgscan-duration': {
                    'required': False,
                    'type': 'int'
                },
                'ap-bgscan-idle': {
                    'required': False,
                    'type': 'int'
                },
                'ap-bgscan-intv': {
                    'required': False,
                    'type': 'int'
                },
                'ap-bgscan-period': {
                    'required': False,
                    'type': 'int'
                },
                'ap-bgscan-report-intv': {
                    'required': False,
                    'type': 'int'
                },
                'ap-fgscan-report-intv': {
                    'required': False,
                    'type': 'int'
                },
                'ap-scan': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-scan-passive': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'asleap-attack': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'assoc-flood-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'assoc-flood-time': {
                    'required': False,
                    'type': 'int'
                },
                'assoc-frame-flood': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auth-flood-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'auth-flood-time': {
                    'required': False,
                    'type': 'int'
                },
                'auth-frame-flood': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'type': 'str'
                },
                'deauth-broadcast': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'deauth-unknown-src-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-fail-flood': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'eapol-fail-intv': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-fail-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-logoff-flood': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'eapol-logoff-intv': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-logoff-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-pre-fail-flood': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'eapol-pre-fail-intv': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-pre-fail-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-pre-succ-flood': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'eapol-pre-succ-intv': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-pre-succ-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-start-flood': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'eapol-start-intv': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-start-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-succ-flood': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'eapol-succ-intv': {
                    'required': False,
                    'type': 'int'
                },
                'eapol-succ-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'invalid-mac-oui': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'long-duration-attack': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'long-duration-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'null-ssid-probe-resp': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sensor-mode': {
                    'required': False,
                    'choices': [
                        'disable',
                        'foreign',
                        'both'
                    ],
                    'type': 'str'
                },
                'spoofed-deauth': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'weak-wep-iv': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'wireless-bridge': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'widsprofile'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
