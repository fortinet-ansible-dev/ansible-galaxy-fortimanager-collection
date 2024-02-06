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
module: fmgr_application_list
short_description: Configure application control lists.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    application_list:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app-replacemsg:
                type: str
                description: Deprecated, please rename it to app_replacemsg. Enable/disable replacement messages for blocked applications.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comments
            deep-app-inspection:
                type: str
                description: Deprecated, please rename it to deep_app_inspection. Enable/disable deep application inspection.
                choices:
                    - 'disable'
                    - 'enable'
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Pass or block traffic, or reset connection for traffic from this application.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                    application:
                        type: raw
                        description: (list) ID of allowed applications.
                    behavior:
                        type: raw
                        description: (list) Application behavior filter.
                    category:
                        type: raw
                        description: (list or str) Category ID list.
                    id:
                        type: int
                        description: Entry ID.
                    log:
                        type: str
                        description: Enable/disable logging for this application list.
                        choices:
                            - 'disable'
                            - 'enable'
                    log-packet:
                        type: str
                        description: Deprecated, please rename it to log_packet. Enable/disable packet logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    parameters:
                        type: list
                        elements: dict
                        description: Parameters.
                        suboptions:
                            id:
                                type: int
                                description: Parameter ID.
                            value:
                                type: str
                                description: Parameter value.
                            members:
                                type: list
                                elements: dict
                                description: Members.
                                suboptions:
                                    id:
                                        type: int
                                        description: Parameter.
                                    name:
                                        type: str
                                        description: Parameter name.
                                    value:
                                        type: str
                                        description: Parameter value.
                    per-ip-shaper:
                        type: str
                        description: Deprecated, please rename it to per_ip_shaper. Per-IP traffic shaper.
                    popularity:
                        type: list
                        elements: str
                        description: Application popularity filter
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                    protocols:
                        type: raw
                        description: (list) Application protocol filter.
                    quarantine:
                        type: str
                        description: Quarantine method.
                        choices:
                            - 'none'
                            - 'attacker'
                    quarantine-expiry:
                        type: str
                        description: Deprecated, please rename it to quarantine_expiry. Duration of quarantine.
                    quarantine-log:
                        type: str
                        description: Deprecated, please rename it to quarantine_log. Enable/disable quarantine logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    rate-count:
                        type: int
                        description: Deprecated, please rename it to rate_count. Count of the rate.
                    rate-duration:
                        type: int
                        description: Deprecated, please rename it to rate_duration. Duration
                    rate-mode:
                        type: str
                        description: Deprecated, please rename it to rate_mode. Rate limit mode.
                        choices:
                            - 'periodical'
                            - 'continuous'
                    rate-track:
                        type: str
                        description: Deprecated, please rename it to rate_track. Track the packet protocol field.
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                            - 'dhcp-client-mac'
                            - 'dns-domain'
                    risk:
                        type: raw
                        description: (list) Risk, or impact, of allowing traffic from this application to occur
                    session-ttl:
                        type: int
                        description: Deprecated, please rename it to session_ttl. Session TTL
                    shaper:
                        type: str
                        description: Traffic shaper.
                    shaper-reverse:
                        type: str
                        description: Deprecated, please rename it to shaper_reverse. Reverse traffic shaper.
                    sub-category:
                        type: raw
                        description: (list) Deprecated, please rename it to sub_category. Application Sub-category ID list.
                    technology:
                        type: raw
                        description: (list) Application technology filter.
                    vendor:
                        type: raw
                        description: (list) Application vendor filter.
                    tags:
                        type: str
                        description: Tag filter.
                    exclusion:
                        type: raw
                        description: (list) ID of excluded applications.
            extended-log:
                type: str
                description: Deprecated, please rename it to extended_log. Enable/disable extended logging.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: List name.
                required: true
            options:
                type: list
                elements: str
                description: Basic application protocol signatures allowed by default.
                choices:
                    - 'allow-dns'
                    - 'allow-icmp'
                    - 'allow-http'
                    - 'allow-ssl'
                    - 'allow-quic'
            other-application-action:
                type: str
                description: Deprecated, please rename it to other_application_action. Action for other applications.
                choices:
                    - 'pass'
                    - 'block'
            other-application-log:
                type: str
                description: Deprecated, please rename it to other_application_log. Enable/disable logging for other applications.
                choices:
                    - 'disable'
                    - 'enable'
            p2p-black-list:
                type: list
                elements: str
                description: Deprecated, please rename it to p2p_black_list. P2P applications to be black listed.
                choices:
                    - 'skype'
                    - 'edonkey'
                    - 'bittorrent'
            replacemsg-group:
                type: str
                description: Deprecated, please rename it to replacemsg_group. Replacement message group.
            unknown-application-action:
                type: str
                description: Deprecated, please rename it to unknown_application_action. Pass or block traffic from unknown applications.
                choices:
                    - 'pass'
                    - 'block'
            unknown-application-log:
                type: str
                description: Deprecated, please rename it to unknown_application_log. Enable/disable logging for unknown applications.
                choices:
                    - 'disable'
                    - 'enable'
            control-default-network-services:
                type: str
                description: Deprecated, please rename it to control_default_network_services. Enable/disable enforcement of protocols over selected ports.
                choices:
                    - 'disable'
                    - 'enable'
            default-network-services:
                type: list
                elements: dict
                description: Deprecated, please rename it to default_network_services. Default-Network-Services.
                suboptions:
                    id:
                        type: int
                        description: Entry ID.
                    port:
                        type: int
                        description: Port number.
                    services:
                        type: list
                        elements: str
                        description: Network protocols.
                        choices:
                            - 'http'
                            - 'ssh'
                            - 'telnet'
                            - 'ftp'
                            - 'dns'
                            - 'smtp'
                            - 'pop3'
                            - 'imap'
                            - 'snmp'
                            - 'nntp'
                            - 'https'
                    violation-action:
                        type: str
                        description: Deprecated, please rename it to violation_action. Action for protocols not white listed under selected port.
                        choices:
                            - 'block'
                            - 'monitor'
                            - 'pass'
            enforce-default-app-port:
                type: str
                description: Deprecated, please rename it to enforce_default_app_port. Enable/disable default application port enforcement for allowed ...
                choices:
                    - 'disable'
                    - 'enable'
            force-inclusion-ssl-di-sigs:
                type: str
                description: Deprecated, please rename it to force_inclusion_ssl_di_sigs. Enable/disable forced inclusion of SSL deep inspection signat...
                choices:
                    - 'disable'
                    - 'enable'
            p2p-block-list:
                type: list
                elements: str
                description: Deprecated, please rename it to p2p_block_list. P2P applications to be blocklisted.
                choices:
                    - 'skype'
                    - 'edonkey'
                    - 'bittorrent'
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
    - name: Configure application control lists.
      fortinet.fortimanager.fmgr_application_list:
        adom: ansible
        state: present
        application_list:
          app-replacemsg: enable
          comment: "ansible-test-comment"
          deep-app-inspection: enable
          extended-log: disable
          name: "ansible-test"
          other-application-action: pass
          other-application-log: disable
          unknown-application-action: pass
          unknown-application-log: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the application list
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "application_list"
          params:
            adom: "ansible"
            list: "your_value"
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
        '/pm/config/adom/{adom}/obj/application/list',
        '/pm/config/global/obj/application/list'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/application/list/{list}',
        '/pm/config/global/obj/application/list/{list}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'application_list': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'app-replacemsg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'type': 'str'},
                'deep-app-inspection': {'choices': ['disable', 'enable'], 'type': 'str'},
                'entries': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['pass', 'block', 'reset'], 'type': 'str'},
                        'application': {'type': 'raw'},
                        'behavior': {'type': 'raw'},
                        'category': {'type': 'raw'},
                        'id': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-packet': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'parameters': {
                            'type': 'list',
                            'options': {
                                'id': {'type': 'int'},
                                'value': {'type': 'str'},
                                'members': {
                                    'v_range': [['6.4.0', '']],
                                    'type': 'list',
                                    'options': {
                                        'id': {'v_range': [['6.4.0', '']], 'type': 'int'},
                                        'name': {'v_range': [['6.4.0', '']], 'type': 'str'},
                                        'value': {'v_range': [['6.4.0', '']], 'type': 'str'}
                                    },
                                    'elements': 'dict'
                                }
                            },
                            'elements': 'dict'
                        },
                        'per-ip-shaper': {'type': 'str'},
                        'popularity': {'type': 'list', 'choices': ['1', '2', '3', '4', '5'], 'elements': 'str'},
                        'protocols': {'type': 'raw'},
                        'quarantine': {'choices': ['none', 'attacker'], 'type': 'str'},
                        'quarantine-expiry': {'type': 'str'},
                        'quarantine-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'rate-count': {'type': 'int'},
                        'rate-duration': {'type': 'int'},
                        'rate-mode': {'choices': ['periodical', 'continuous'], 'type': 'str'},
                        'rate-track': {'choices': ['none', 'src-ip', 'dest-ip', 'dhcp-client-mac', 'dns-domain'], 'type': 'str'},
                        'risk': {'type': 'raw'},
                        'session-ttl': {'type': 'int'},
                        'shaper': {'type': 'str'},
                        'shaper-reverse': {'type': 'str'},
                        'sub-category': {'type': 'raw'},
                        'technology': {'type': 'raw'},
                        'vendor': {'type': 'raw'},
                        'tags': {'v_range': [['6.2.0', '6.4.13']], 'type': 'str'},
                        'exclusion': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'extended-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'options': {'type': 'list', 'choices': ['allow-dns', 'allow-icmp', 'allow-http', 'allow-ssl', 'allow-quic'], 'elements': 'str'},
                'other-application-action': {'choices': ['pass', 'block'], 'type': 'str'},
                'other-application-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'p2p-black-list': {'type': 'list', 'choices': ['skype', 'edonkey', 'bittorrent'], 'elements': 'str'},
                'replacemsg-group': {'type': 'str'},
                'unknown-application-action': {'choices': ['pass', 'block'], 'type': 'str'},
                'unknown-application-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'control-default-network-services': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-network-services': {
                    'v_range': [['6.2.0', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'port': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'services': {
                            'v_range': [['6.2.0', '']],
                            'type': 'list',
                            'choices': ['http', 'ssh', 'telnet', 'ftp', 'dns', 'smtp', 'pop3', 'imap', 'snmp', 'nntp', 'https'],
                            'elements': 'str'
                        },
                        'violation-action': {'v_range': [['6.2.0', '']], 'choices': ['block', 'monitor', 'pass'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'enforce-default-app-port': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'force-inclusion-ssl-di-sigs': {'v_range': [['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'p2p-block-list': {'v_range': [['7.0.0', '']], 'type': 'list', 'choices': ['skype', 'edonkey', 'bittorrent'], 'elements': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_list'),
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
