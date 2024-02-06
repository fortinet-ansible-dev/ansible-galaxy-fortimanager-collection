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
module: fmgr_pkg_firewall_multicastpolicy
short_description: Configure multicast NAT policies.
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
    pkg_firewall_multicastpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Accept or deny traffic matching the policy.
                choices:
                    - 'deny'
                    - 'accept'
            auto-asic-offload:
                type: str
                description: Deprecated, please rename it to auto_asic_offload. Enable/disable offloading policy traffic for hardware acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            dnat:
                type: str
                description: IPv4 DNAT address used for multicast destination addresses.
            dstaddr:
                type: raw
                description: (list or str) Destination address objects.
            dstintf:
                type: str
                description: Destination interface name.
            end-port:
                type: int
                description: Deprecated, please rename it to end_port. Integer value for ending TCP/UDP/SCTP destination port in range
            id:
                type: int
                description: Policy ID.
                required: true
            logtraffic:
                type: str
                description: Enable/disable logging traffic accepted by this policy.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            protocol:
                type: int
                description: Integer value for the protocol type as defined by IANA
            snat:
                type: str
                description: Enable/disable substitution of the outgoing interface IP address for the original source IP address
                choices:
                    - 'disable'
                    - 'enable'
            snat-ip:
                type: str
                description: Deprecated, please rename it to snat_ip. IPv4 address to be used as the source address for NATed traffic.
            srcaddr:
                type: raw
                description: (list or str) Source address objects.
            srcintf:
                type: str
                description: Source interface name.
            start-port:
                type: int
                description: Deprecated, please rename it to start_port. Integer value for starting TCP/UDP/SCTP destination port in range
            status:
                type: str
                description: Enable/disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: Comment.
            uuid:
                type: str
                description: Universally Unique Identifier
            name:
                type: str
                description: Policy name.
            traffic-shaper:
                type: str
                description: Deprecated, please rename it to traffic_shaper. Traffic shaper to apply to traffic forwarded by the multicast policy.
            ips-sensor:
                type: str
                description: Deprecated, please rename it to ips_sensor. Name of an existing IPS sensor.
            utm-status:
                type: str
                description: Deprecated, please rename it to utm_status. Enable to add an IPS security profile to the policy.
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
    - name: Configure multicast NAT policies.
      fortinet.fortimanager.fmgr_pkg_firewall_multicastpolicy:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_multicastpolicy:
          action: accept # <value in [deny, accept]>
          dstaddr: all
          dstintf: any
          id: 2
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
    - name: Retrieve all the multicast NAT policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_multicastpolicy"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            multicast-policy: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy/{multicast-policy}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'pkg_firewall_multicastpolicy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'accept'], 'type': 'str'},
                'auto-asic-offload': {'v_range': [['6.0.0', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dnat': {'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'dstintf': {'type': 'str'},
                'end-port': {'type': 'int'},
                'id': {'required': True, 'type': 'int'},
                'logtraffic': {'choices': ['disable', 'enable', 'all', 'utm'], 'type': 'str'},
                'protocol': {'type': 'int'},
                'snat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'snat-ip': {'type': 'str'},
                'srcaddr': {'type': 'raw'},
                'srcintf': {'type': 'str'},
                'start-port': {'type': 'int'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'uuid': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'name': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'traffic-shaper': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'ips-sensor': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'utm-status': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_multicastpolicy'),
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
