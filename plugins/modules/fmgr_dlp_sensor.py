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
module: fmgr_dlp_sensor
short_description: Configure DLP sensors.
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
    dlp_sensor:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            dlp_log:
                aliases: ['dlp-log']
                type: str
                description: Enable/disable DLP logging.
                choices: ['disable', 'enable']
            extended_log:
                aliases: ['extended-log']
                type: str
                description: Enable/disable extended logging for data leak prevention.
                choices: ['disable', 'enable']
            filter:
                type: list
                elements: dict
                description: Filter.
                suboptions:
                    action:
                        type: str
                        description: Action to take with content that this DLP sensor matches.
                        choices: ['log-only', 'block', 'exempt', 'ban', 'ban-sender',
                                  'quarantine-ip', 'quarantine-port', 'none', 'allow']
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
                        choices: ['credit-card', 'ssn', 'regexp', 'file-type', 'file-size',
                                  'fingerprint', 'watermark', 'encrypted', 'file-type-and-size']
                    fp_sensitivity:
                        aliases: ['fp-sensitivity']
                        type: raw
                        description: (list or str) Select a DLP file pattern sensitivity to match.
                    id:
                        type: int
                        description: ID.
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
                        choices: ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mm1', 'mm3', 'mm4',
                                  'mm7', 'mapi', 'aim', 'icq', 'msn', 'yahoo', 'http-get',
                                  'http-post', 'ssh', 'cifs']
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
            flow_based:
                aliases: ['flow-based']
                type: str
                description: Enable/disable flow-based DLP.
                choices: ['disable', 'enable']
            full_archive_proto:
                aliases: ['full-archive-proto']
                type: list
                elements: str
                description: Protocols to always content archive.
                choices: ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mm1', 'mm3', 'mm4', 'mm7',
                          'mapi', 'aim', 'icq', 'msn', 'yahoo', 'http-get', 'http-post', 'ssh',
                          'cifs']
            nac_quar_log:
                aliases: ['nac-quar-log']
                type: str
                description: Enable/disable NAC quarantine logging.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Name of the DLP sensor.
                required: true
            options:
                type: str
                description: Configure DLP options.
                choices: ['strict-file']
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group used by this DLP sensor.
            summary_proto:
                aliases: ['summary-proto']
                type: list
                elements: str
                description: Protocols to always log summary.
                choices: ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mm1', 'mm3', 'mm4', 'mm7',
                          'mapi', 'aim', 'icq', 'msn', 'yahoo', 'http-get', 'http-post', 'ssh',
                          'cifs']
            feature_set:
                aliases: ['feature-set']
                type: str
                description: Flow/proxy feature set.
                choices: ['proxy', 'flow']
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    count:
                        type: int
                        description: Count of dictionary matches to trigger sensor entry match
                    dictionary:
                        type: str
                        description: Select a DLP dictionary.
                    id:
                        type: int
                        description: ID.
                    status:
                        type: str
                        description: Enable/disable this entry.
                        choices: ['disable', 'enable']
            eval:
                type: str
                description: Expression to evaluate.
            match_type:
                aliases: ['match-type']
                type: str
                description: Logical relation between entries
                choices: ['match-all', 'match-any', 'match-eval']
            fgd_id:
                aliases: ['fgd-id']
                type: int
                description: ID of object in FortiGuard database.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure DLP sensors.
      fortinet.fortimanager.fmgr_dlp_sensor:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        dlp_sensor:
          name: "your value" # Required variable, string
          # comment: <string>
          # dlp_log: <value in [disable, enable]>
          # extended_log: <value in [disable, enable]>
          # filter:
          #   - action: <value in [log-only, block, exempt, ...]>
          #     archive: <value in [disable, enable, summary-only]>
          #     company_identifier: <string>
          #     expiry: <string>
          #     file_size: <integer>
          #     file_type: <string>
          #     filter_by: <value in [credit-card, ssn, regexp, ...]>
          #     fp_sensitivity: <list or string>
          #     id: <integer>
          #     match_percentage: <integer>
          #     name: <string>
          #     proto: ["imap", "smtp", "pop3", "ftp", "nntp", "mm1", "mm3", "mm4", "mm7", "mapi",
          #             "aim", "icq", "msn", "yahoo", "http-get", "http-post", "ssh", "cifs"]
          #     regexp: <string>
          #     severity: <value in [info, low, medium, ...]>
          #     type: <value in [file, message]>
          #     sensitivity: <list or string>
          # flow_based: <value in [disable, enable]>
          # full_archive_proto: ["imap", "smtp", "pop3", "ftp", "nntp", "mm1", "mm3", "mm4",
          #                      "mm7", "mapi", "aim", "icq", "msn", "yahoo", "http-get",
          #                      "http-post", "ssh", "cifs"]
          # nac_quar_log: <value in [disable, enable]>
          # options: <value in [strict-file]>
          # replacemsg_group: <string>
          # summary_proto: ["imap", "smtp", "pop3", "ftp", "nntp", "mm1", "mm3", "mm4", "mm7",
          #                 "mapi", "aim", "icq", "msn", "yahoo", "http-get", "http-post", "ssh",
          #                 "cifs"]
          # feature_set: <value in [proxy, flow]>
          # entries:
          #   - count: <integer>
          #     dictionary: <string>
          #     id: <integer>
          #     status: <value in [disable, enable]>
          # eval: <string>
          # match_type: <value in [match-all, match-any, match-eval]>
          # fgd_id: <integer>
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
        '/pm/config/adom/{adom}/obj/dlp/sensor',
        '/pm/config/global/obj/dlp/sensor'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dlp_sensor': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'dlp-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'extended-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'filter': {
                    'type': 'list',
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
                            'choices': [
                                'credit-card', 'ssn', 'regexp', 'file-type', 'file-size', 'fingerprint', 'watermark', 'encrypted', 'file-type-and-size'
                            ],
                            'type': 'str'
                        },
                        'fp-sensitivity': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'raw'},
                        'id': {'type': 'int'},
                        'match-percentage': {'type': 'int'},
                        'name': {'type': 'str'},
                        'proto': {
                            'type': 'list',
                            'choices': [
                                'imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mm1', 'mm3', 'mm4', 'mm7', 'mapi', 'aim', 'icq', 'msn', 'yahoo', 'http-get',
                                'http-post', 'ssh', 'cifs'
                            ],
                            'elements': 'str'
                        },
                        'regexp': {'type': 'str'},
                        'severity': {'choices': ['info', 'low', 'medium', 'high', 'critical'], 'type': 'str'},
                        'type': {'choices': ['file', 'message'], 'type': 'str'},
                        'sensitivity': {'v_range': [['6.2.0', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'flow-based': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'full-archive-proto': {
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mm1', 'mm3', 'mm4', 'mm7', 'mapi', 'aim', 'icq', 'msn', 'yahoo', 'http-get', 'http-post',
                        'ssh', 'cifs'
                    ],
                    'elements': 'str'
                },
                'nac-quar-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'options': {'v_range': [['6.0.0', '7.2.0']], 'choices': ['strict-file'], 'type': 'str'},
                'replacemsg-group': {'type': 'str'},
                'summary-proto': {
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mm1', 'mm3', 'mm4', 'mm7', 'mapi', 'aim', 'icq', 'msn', 'yahoo', 'http-get', 'http-post',
                        'ssh', 'cifs'
                    ],
                    'elements': 'str'
                },
                'feature-set': {'v_range': [['6.4.0', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'entries': {
                    'v_range': [['7.2.0', '']],
                    'type': 'list',
                    'options': {
                        'count': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'dictionary': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'eval': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'match-type': {'v_range': [['7.2.0', '']], 'choices': ['match-all', 'match-any', 'match-eval'], 'type': 'str'},
                'fgd-id': {'v_range': [['7.6.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_sensor'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
