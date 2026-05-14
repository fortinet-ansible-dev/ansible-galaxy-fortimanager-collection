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
module: fmgr_dlp_sensor_filter
short_description: Set up DLP filters for this sensor.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    sensor:
        description: The parameter (sensor) in requested url.
        type: str
        required: true
    dlp_sensor_filter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action to take with content that this DLP sensor matches.
                choices: ['log-only', 'block', 'exempt', 'ban', 'ban-sender', 'quarantine-ip',
                          'quarantine-port', 'none', 'allow']
            archive:
                type: str
                description: Enable/disable DLP archiving.
                choices: ['disable', 'enable', 'summary-only']
            company_identifier:
                aliases: ['company-identifier']
                type: str
                description: Enter a company identifier watermark to match.
            expiry:
                type: str
                description: Quarantine duration in days, hours, minutes format
            file_size:
                aliases: ['file-size']
                type: int
                description: Match files this size or larger
            file_type:
                aliases: ['file-type']
                type: str
                description: Select the number of a DLP file pattern table to match.
            filter_by:
                aliases: ['filter-by']
                type: str
                description: Select the type of content to match.
                choices: ['credit-card', 'ssn', 'regexp', 'file-type', 'file-size', 'fingerprint',
                          'watermark', 'encrypted', 'file-type-and-size']
            fp_sensitivity:
                aliases: ['fp-sensitivity']
                type: raw
                description: (list or str) Select a DLP file pattern sensitivity to match.
            id:
                type: int
                description: ID.
                required: true
            match_percentage:
                aliases: ['match-percentage']
                type: int
                description: Percentage of fingerprints in the fingerprint databases designated with the selected fp-sensitivity to match.
            name:
                type: str
                description: Filter name.
            proto:
                type: list
                elements: str
                description: Check messages or files over one or more of these protocols.
                choices: ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mm1', 'mm3', 'mm4', 'mm7',
                          'mapi', 'aim', 'icq', 'msn', 'yahoo', 'http-get', 'http-post', 'ssh',
                          'cifs']
            regexp:
                type: str
                description: Enter a regular expression to match
            severity:
                type: str
                description: Select the severity or threat level that matches this filter.
                choices: ['info', 'low', 'medium', 'high', 'critical']
            type:
                type: str
                description: Select whether to check the content of messages
                choices: ['file', 'message']
            sensitivity:
                type: raw
                description: (list or str) Select a DLP file pattern sensitivity to match.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Set up DLP filters for this sensor.
      fortinet.fortimanager.fmgr_dlp_sensor_filter:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        sensor: <your own value>
        state: present # <value in [present, absent]>
        dlp_sensor_filter:
          id: 0 # Required variable, integer
          # action: <value in [log-only, block, exempt, ...]>
          # archive: <value in [disable, enable, summary-only]>
          # company_identifier: <string>
          # expiry: <string>
          # file_size: <integer>
          # file_type: <string>
          # filter_by: <value in [credit-card, ssn, regexp, ...]>
          # fp_sensitivity: <list or string>
          # match_percentage: <integer>
          # name: <string>
          # proto: ["imap", "smtp", "pop3", "ftp", "nntp", "mm1", "mm3", "mm4", "mm7", "mapi",
          #         "aim", "icq", "msn", "yahoo", "http-get", "http-post", "ssh", "cifs"]
          # regexp: <string>
          # severity: <value in [info, low, medium, ...]>
          # type: <value in [file, message]>
          # sensitivity: <list or string>
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
        '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/filter',
        '/pm/config/global/obj/dlp/sensor/{sensor}/filter'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'sensor': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dlp_sensor_filter': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {
                    'choices': ['log-only', 'block', 'exempt', 'ban', 'ban-sender', 'quarantine-ip', 'quarantine-port', 'none', 'allow'],
                    'type': 'str'
                },
                'archive': {'choices': ['disable', 'enable', 'summary-only'], 'type': 'str'},
                'company-identifier': {'type': 'str'},
                'expiry': {'type': 'str'},
                'file-size': {'type': 'int'},
                'file-type': {'type': 'str'},
                'filter-by': {
                    'choices': ['credit-card', 'ssn', 'regexp', 'file-type', 'file-size', 'fingerprint', 'watermark', 'encrypted', 'file-type-and-size'],
                    'type': 'str'
                },
                'fp-sensitivity': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'raw'},
                'id': {'required': True, 'type': 'int'},
                'match-percentage': {'type': 'int'},
                'name': {'type': 'str'},
                'proto': {
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mm1', 'mm3', 'mm4', 'mm7', 'mapi', 'aim', 'icq', 'msn', 'yahoo', 'http-get', 'http-post',
                        'ssh', 'cifs'
                    ],
                    'elements': 'str'
                },
                'regexp': {'type': 'str'},
                'severity': {'choices': ['info', 'low', 'medium', 'high', 'critical'], 'type': 'str'},
                'type': {'choices': ['file', 'message'], 'type': 'str'},
                'sensitivity': {'v_range': [['6.2.0', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_sensor_filter'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
