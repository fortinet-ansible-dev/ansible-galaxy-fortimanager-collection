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
module: fmgr_pkg_firewall_policy64
short_description: Configure IPv6 to IPv4 policies.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_policy64:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action.
                choices:
                    - 'deny'
                    - 'accept'
            comments:
                type: str
                description: Comment.
            dstaddr:
                type: raw
                description: (list or str) Destination address name.
            dstintf:
                type: str
                description: Destination interface name.
            fixedport:
                type: str
                description: Enable/disable policy fixed port.
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: Enable/disable policy64 IP pool.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: Enable/disable policy log traffic.
                choices:
                    - 'disable'
                    - 'enable'
            per-ip-shaper:
                type: str
                description: Deprecated, please rename it to per_ip_shaper. Per-IP traffic shaper.
            permit-any-host:
                type: str
                description: Deprecated, please rename it to permit_any_host. Enable/disable permit any host in.
                choices:
                    - 'disable'
                    - 'enable'
            policyid:
                type: int
                description: Policy ID.
                required: true
            poolname:
                type: raw
                description: (list or str) Policy IP pool names.
            schedule:
                type: str
                description: Schedule name.
            service:
                type: raw
                description: (list or str) Service name.
            srcaddr:
                type: raw
                description: (list or str) Source address name.
            srcintf:
                type: str
                description: Source interface name.
            status:
                type: str
                description: Enable/disable policy status.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: Applied object tags.
            tcp-mss-receiver:
                type: int
                description: Deprecated, please rename it to tcp_mss_receiver. TCP MSS value of receiver.
            tcp-mss-sender:
                type: int
                description: Deprecated, please rename it to tcp_mss_sender. TCP MSS value of sender.
            traffic-shaper:
                type: str
                description: Deprecated, please rename it to traffic_shaper. Traffic shaper.
            traffic-shaper-reverse:
                type: str
                description: Deprecated, please rename it to traffic_shaper_reverse. Reverse traffic shaper.
            uuid:
                type: str
                description: Universally Unique Identifier
            logtraffic-start:
                type: str
                description: Deprecated, please rename it to logtraffic_start. Record logs when a session starts and ends.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Policy name.
            policy-offload:
                type: str
                description: Deprecated, please rename it to policy_offload. Enable/disable hardware session setup for CGNAT.
                choices:
                    - 'disable'
                    - 'enable'
            cgn-session-quota:
                type: int
                description: Deprecated, please rename it to cgn_session_quota. Session quota
            cgn-eif:
                type: str
                description: Deprecated, please rename it to cgn_eif. Enable/disable CGN endpoint independent filtering.
                choices:
                    - 'disable'
                    - 'enable'
            cgn-log-server-grp:
                type: str
                description: Deprecated, please rename it to cgn_log_server_grp. NP log server group name
            cgn-resource-quota:
                type: int
                description: Deprecated, please rename it to cgn_resource_quota. Resource quota
            cgn-eim:
                type: str
                description: Deprecated, please rename it to cgn_eim. Enable/disable CGN endpoint independent mapping.
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
    - name: Configure IPv6 to IPv4 policies.
      fortinet.fortimanager.fmgr_pkg_firewall_policy64:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_policy64:
          action: accept # <value in [deny, accept]>
          comments: ansible-comment
          dstaddr: all
          dstintf: any
          policyid: 1
          schedule: always
          service: ALL
          srcaddr: all
          srcintf: any
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv6 to IPv4 policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_policy64"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            policy64: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64/{policy64}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'pkg_firewall_policy64': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'accept'], 'type': 'str'},
                'comments': {'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'dstintf': {'type': 'str'},
                'fixedport': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ippool': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic': {'choices': ['disable', 'enable'], 'type': 'str'},
                'per-ip-shaper': {'type': 'str'},
                'permit-any-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'policyid': {'required': True, 'type': 'int'},
                'poolname': {'type': 'raw'},
                'schedule': {'type': 'str'},
                'service': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'srcintf': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.0.0', '6.4.13']], 'type': 'str'},
                'tcp-mss-receiver': {'type': 'int'},
                'tcp-mss-sender': {'type': 'int'},
                'traffic-shaper': {'type': 'str'},
                'traffic-shaper-reverse': {'type': 'str'},
                'uuid': {'type': 'str'},
                'logtraffic-start': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'policy-offload': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-session-quota': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                'cgn-eif': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-log-server-grp': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'str'},
                'cgn-resource-quota': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                'cgn-eim': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_policy64'),
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
