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
    dlp_sensor:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            dlp-log:
                type: str
                description: Deprecated, please rename it to dlp_log. Enable/disable DLP logging.
                choices:
                    - 'disable'
                    - 'enable'
            extended-log:
                type: str
                description: Deprecated, please rename it to extended_log. Enable/disable extended logging for data leak prevention.
                choices:
                    - 'disable'
                    - 'enable'
            filter:
                type: list
                elements: dict
                description: Filter.
                suboptions:
                    action:
                        type: str
                        description: Action to take with content that this DLP sensor matches.
                        choices:
                            - 'log-only'
                            - 'block'
                            - 'exempt'
                            - 'ban'
                            - 'ban-sender'
                            - 'quarantine-ip'
                            - 'quarantine-port'
                            - 'none'
                            - 'allow'
                    archive:
                        type: str
                        description: Enable/disable DLP archiving.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'summary-only'
                    company-identifier:
                        type: str
                        description: Deprecated, please rename it to company_identifier. Enter a company identifier watermark to match.
                    expiry:
                        type: str
                        description: Quarantine duration in days, hours, minutes format
                    file-size:
                        type: int
                        description: Deprecated, please rename it to file_size. Match files this size or larger
                    file-type:
                        type: str
                        description: Deprecated, please rename it to file_type. Select the number of a DLP file pattern table to match.
                    filter-by:
                        type: str
                        description: Deprecated, please rename it to filter_by. Select the type of content to match.
                        choices:
                            - 'credit-card'
                            - 'ssn'
                            - 'regexp'
                            - 'file-type'
                            - 'file-size'
                            - 'fingerprint'
                            - 'watermark'
                            - 'encrypted'
                            - 'file-type-and-size'
                    fp-sensitivity:
                        type: raw
                        description: (list or str) Deprecated, please rename it to fp_sensitivity. Select a DLP file pattern sensitivity to match.
                    id:
                        type: int
                        description: ID.
                    match-percentage:
                        type: int
                        description: Deprecated, please rename it to match_percentage. Percentage of fingerprints in the fingerprint databases designat...
                    name:
                        type: str
                        description: Filter name.
                    proto:
                        type: list
                        elements: str
                        description: Check messages or files over one or more of these protocols.
                        choices:
                            - 'imap'
                            - 'smtp'
                            - 'pop3'
                            - 'ftp'
                            - 'nntp'
                            - 'mm1'
                            - 'mm3'
                            - 'mm4'
                            - 'mm7'
                            - 'mapi'
                            - 'aim'
                            - 'icq'
                            - 'msn'
                            - 'yahoo'
                            - 'http-get'
                            - 'http-post'
                            - 'ssh'
                            - 'cifs'
                    regexp:
                        type: str
                        description: Enter a regular expression to match
                    severity:
                        type: str
                        description: Select the severity or threat level that matches this filter.
                        choices:
                            - 'info'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    type:
                        type: str
                        description: Select whether to check the content of messages
                        choices:
                            - 'file'
                            - 'message'
                    sensitivity:
                        type: raw
                        description: (list or str) Select a DLP file pattern sensitivity to match.
            flow-based:
                type: str
                description: Deprecated, please rename it to flow_based. Enable/disable flow-based DLP.
                choices:
                    - 'disable'
                    - 'enable'
            full-archive-proto:
                type: list
                elements: str
                description: Deprecated, please rename it to full_archive_proto. Protocols to always content archive.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'ftp'
                    - 'nntp'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'mapi'
                    - 'aim'
                    - 'icq'
                    - 'msn'
                    - 'yahoo'
                    - 'http-get'
                    - 'http-post'
                    - 'ssh'
                    - 'cifs'
            nac-quar-log:
                type: str
                description: Deprecated, please rename it to nac_quar_log. Enable/disable NAC quarantine logging.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Name of the DLP sensor.
                required: true
            options:
                type: str
                description: Configure DLP options.
                choices:
                    - 'strict-file'
            replacemsg-group:
                type: str
                description: Deprecated, please rename it to replacemsg_group. Replacement message group used by this DLP sensor.
            summary-proto:
                type: list
                elements: str
                description: Deprecated, please rename it to summary_proto. Protocols to always log summary.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'ftp'
                    - 'nntp'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'mapi'
                    - 'aim'
                    - 'icq'
                    - 'msn'
                    - 'yahoo'
                    - 'http-get'
                    - 'http-post'
                    - 'ssh'
                    - 'cifs'
            feature-set:
                type: str
                description: Deprecated, please rename it to feature_set. Flow/proxy feature set.
                choices:
                    - 'proxy'
                    - 'flow'
            entries:
                type: list
                elements: dict
                description: No description.
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
                        choices:
                            - 'disable'
                            - 'enable'
            eval:
                type: str
                description: Expression to evaluate.
            match-type:
                type: str
                description: Deprecated, please rename it to match_type. Logical relation between entries
                choices:
                    - 'match-all'
                    - 'match-any'
                    - 'match-eval'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure DLP sensors.
      fortinet.fortimanager.fmgr_dlp_sensor:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        dlp_sensor:
          comment: <string>
          dlp_log: <value in [disable, enable]>
          extended_log: <value in [disable, enable]>
          filter:
            -
              action: <value in [log-only, block, exempt, ...]>
              archive: <value in [disable, enable, summary-only]>
              company_identifier: <string>
              expiry: <string>
              file_size: <integer>
              file_type: <string>
              filter_by: <value in [credit-card, ssn, regexp, ...]>
              fp_sensitivity: <list or string>
              id: <integer>
              match_percentage: <integer>
              name: <string>
              proto:
                - imap
                - smtp
                - pop3
                - ftp
                - nntp
                - mm1
                - mm3
                - mm4
                - mm7
                - mapi
                - aim
                - icq
                - msn
                - yahoo
                - http-get
                - http-post
                - ssh
                - cifs
              regexp: <string>
              severity: <value in [info, low, medium, ...]>
              type: <value in [file, message]>
              sensitivity: <list or string>
          flow_based: <value in [disable, enable]>
          full_archive_proto:
            - imap
            - smtp
            - pop3
            - ftp
            - nntp
            - mm1
            - mm3
            - mm4
            - mm7
            - mapi
            - aim
            - icq
            - msn
            - yahoo
            - http-get
            - http-post
            - ssh
            - cifs
          nac_quar_log: <value in [disable, enable]>
          name: <string>
          options: <value in [strict-file]>
          replacemsg_group: <string>
          summary_proto:
            - imap
            - smtp
            - pop3
            - ftp
            - nntp
            - mm1
            - mm3
            - mm4
            - mm7
            - mapi
            - aim
            - icq
            - msn
            - yahoo
            - http-get
            - http-post
            - ssh
            - cifs
          feature_set: <value in [proxy, flow]>
          entries:
            -
              count: <integer>
              dictionary: <string>
              id: <integer>
              status: <value in [disable, enable]>
          eval: <string>
          match_type: <value in [match-all, match-any, match-eval]>
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/dlp/sensor',
        '/pm/config/global/obj/dlp/sensor'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}',
        '/pm/config/global/obj/dlp/sensor/{sensor}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'dlp_sensor': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
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
                        'fp-sensitivity': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
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
                'match-type': {'v_range': [['7.2.0', '']], 'choices': ['match-all', 'match-any', 'match-eval'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_sensor'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
