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
module: fmgr_pkg_firewall_hyperscalepolicy6
short_description: Configure IPv6 policies.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    pkg_firewall_hyperscalepolicy6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
            auto-asic-offload:
                type: str
                description: Deprecated, please rename it to auto_asic_offload. Enable/disable policy traffic ASIC offloading.
                choices:
                    - 'disable'
                    - 'enable'
            cgn-log-server-grp:
                type: str
                description: Deprecated, please rename it to cgn_log_server_grp. NP log server group name
            comments:
                type: str
                description: Comment.
            dstaddr:
                type: raw
                description: (list or str) No description.
            dstaddr-negate:
                type: str
                description: Deprecated, please rename it to dstaddr_negate. When enabled dstaddr specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            dstintf:
                type: raw
                description: (list or str) No description.
            name:
                type: str
                description: Policy name.
            policy-offload:
                type: str
                description: Deprecated, please rename it to policy_offload. Enable/disable offloading policy configuration to CP processors.
                choices:
                    - 'disable'
                    - 'enable'
            policyid:
                type: int
                description: Policy ID
                required: true
            service:
                type: raw
                description: (list or str) No description.
            service-negate:
                type: str
                description: Deprecated, please rename it to service_negate. When enabled service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr:
                type: raw
                description: (list or str) No description.
            srcaddr-negate:
                type: str
                description: Deprecated, please rename it to srcaddr_negate. When enabled srcaddr specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcintf:
                type: raw
                description: (list or str) No description.
            status:
                type: str
                description: Enable or disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            tcp-timeout-pid:
                type: str
                description: Deprecated, please rename it to tcp_timeout_pid. TCP timeout profile ID
            traffic-shaper:
                type: str
                description: Deprecated, please rename it to traffic_shaper. Reverse traffic shaper.
            traffic-shaper-reverse:
                type: str
                description: Deprecated, please rename it to traffic_shaper_reverse. Reverse traffic shaper.
            udp-timeout-pid:
                type: str
                description: Deprecated, please rename it to udp_timeout_pid. UDP timeout profile ID
            uuid:
                type: str
                description: Universally Unique Identifier
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
    - name: Configure IPv6 policies.
      fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy6:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_hyperscalepolicy6:
          action: <value in [deny, accept, ipsec]>
          auto_asic_offload: <value in [disable, enable]>
          cgn_log_server_grp: <string>
          comments: <string>
          dstaddr: <list or string>
          dstaddr_negate: <value in [disable, enable]>
          dstintf: <list or string>
          name: <string>
          policy_offload: <value in [disable, enable]>
          policyid: <integer>
          service: <list or string>
          service_negate: <value in [disable, enable]>
          srcaddr: <list or string>
          srcaddr_negate: <value in [disable, enable]>
          srcintf: <list or string>
          status: <value in [disable, enable]>
          tcp_timeout_pid: <string>
          traffic_shaper: <string>
          traffic_shaper_reverse: <string>
          udp_timeout_pid: <string>
          uuid: <string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy6'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy6/{hyperscale-policy6}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'pkg_firewall_hyperscalepolicy6': {
            'type': 'dict',
            'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']],
            'options': {
                'action': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'choices': ['deny', 'accept', 'ipsec'], 'type': 'str'},
                'auto-asic-offload': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-log-server-grp': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'str'},
                'comments': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'str'},
                'dstaddr': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'raw'},
                'dstaddr-negate': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstintf': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'raw'},
                'name': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'str'},
                'policy-offload': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policyid': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'required': True, 'type': 'int'},
                'service': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'raw'},
                'service-negate': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'raw'},
                'srcaddr-negate': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcintf': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'raw'},
                'status': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-timeout-pid': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'str'},
                'traffic-shaper': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'str'},
                'traffic-shaper-reverse': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'str'},
                'udp-timeout-pid': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'str'},
                'uuid': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '7.2.0']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_hyperscalepolicy6'),
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
