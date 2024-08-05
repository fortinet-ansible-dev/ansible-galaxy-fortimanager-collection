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
module: fmgr_firewall_ippool_dynamicmapping
short_description: Configure IPv4 IP pools.
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
    ippool:
        description: The parameter (ippool) in requested url.
        type: str
        required: true
    firewall_ippool_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _scope:
                type: list
                elements: dict
                description: Scope.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            arp-intf:
                type: str
                description: Deprecated, please rename it to arp_intf. Arp intf.
            arp-reply:
                type: str
                description: Deprecated, please rename it to arp_reply. Arp reply.
                choices:
                    - 'disable'
                    - 'enable'
            associated-interface:
                type: str
                description: Deprecated, please rename it to associated_interface. Associated interface.
            block-size:
                type: int
                description: Deprecated, please rename it to block_size. Block size.
            comments:
                type: str
                description: Comments.
            endip:
                type: str
                description: Endip.
            num-blocks-per-user:
                type: int
                description: Deprecated, please rename it to num_blocks_per_user. Num blocks per user.
            pba-timeout:
                type: int
                description: Deprecated, please rename it to pba_timeout. Pba timeout.
            permit-any-host:
                type: str
                description: Deprecated, please rename it to permit_any_host. Permit any host.
                choices:
                    - 'disable'
                    - 'enable'
            source-endip:
                type: str
                description: Deprecated, please rename it to source_endip. Source endip.
            source-startip:
                type: str
                description: Deprecated, please rename it to source_startip. Source startip.
            startip:
                type: str
                description: Startip.
            type:
                type: str
                description: Type.
                choices:
                    - 'overload'
                    - 'one-to-one'
                    - 'fixed-port-range'
                    - 'port-block-allocation'
                    - 'cgn-resource-allocation'
            cgn-block-size:
                type: int
                description: Deprecated, please rename it to cgn_block_size. Cgn block size.
            cgn-client-endip:
                type: str
                description: Deprecated, please rename it to cgn_client_endip. Cgn client endip.
            cgn-client-startip:
                type: str
                description: Deprecated, please rename it to cgn_client_startip. Cgn client startip.
            cgn-fixedalloc:
                type: str
                description: Deprecated, please rename it to cgn_fixedalloc. Cgn fixedalloc.
                choices:
                    - 'disable'
                    - 'enable'
            cgn-overload:
                type: str
                description: Deprecated, please rename it to cgn_overload. Cgn overload.
                choices:
                    - 'disable'
                    - 'enable'
            cgn-port-end:
                type: int
                description: Deprecated, please rename it to cgn_port_end. Cgn port end.
            cgn-port-start:
                type: int
                description: Deprecated, please rename it to cgn_port_start. Cgn port start.
            cgn-spa:
                type: str
                description: Deprecated, please rename it to cgn_spa. Cgn spa.
                choices:
                    - 'disable'
                    - 'enable'
            utilization-alarm-clear:
                type: int
                description: Deprecated, please rename it to utilization_alarm_clear. Utilization alarm clear.
            utilization-alarm-raise:
                type: int
                description: Deprecated, please rename it to utilization_alarm_raise. Utilization alarm raise.
            endport:
                type: int
                description: Final port number
            port-per-user:
                type: int
                description: Deprecated, please rename it to port_per_user. Number of port for each user
            startport:
                type: int
                description: First port number
            add-nat64-route:
                type: str
                description: Deprecated, please rename it to add_nat64_route. Enable/disable adding NAT64 route.
                choices:
                    - 'disable'
                    - 'enable'
            cgn-client-ipv6shift:
                type: int
                description: Deprecated, please rename it to cgn_client_ipv6shift. IPv6 shift for fixed-allocation.
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            subnet-broadcast-in-ippool:
                type: str
                description: Deprecated, please rename it to subnet_broadcast_in_ippool. Enable/disable inclusion of the subnetwork address and broadca...
                choices:
                    - 'disable'
                    - 'enable'
            exclude-ip:
                type: raw
                description: (list) Deprecated, please rename it to exclude_ip. Exclude IPs x.
            pba-interim-log:
                type: int
                description: Deprecated, please rename it to pba_interim_log. Port block allocation interim logging interval
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
    - name: Configure dynamic mappings of IPv4 IP pool
      fortinet.fortimanager.fmgr_firewall_ippool_dynamicmapping:
        bypass_validation: false
        adom: ansible
        ippool: "ansible-test" # name
        state: present
        firewall_ippool_dynamicmapping:
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          comments: "ansible-comment"
          endip: "222.222.222.253"
          startip: "222.222.222.0"
          type: overload # <value in [overload, one-to-one, fixed-port-range, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings of IPv4 IP pool
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_ippool_dynamicmapping"
          params:
            adom: "ansible"
            ippool: "ansible-test" # name
            dynamic_mapping: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}/dynamic_mapping',
        '/pm/config/global/obj/firewall/ippool/{ippool}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'ippool']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'ippool': {'required': True, 'type': 'str'},
        'firewall_ippool_dynamicmapping': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'arp-intf': {'type': 'str'},
                'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'associated-interface': {'type': 'str'},
                'block-size': {'type': 'int'},
                'comments': {'type': 'str'},
                'endip': {'type': 'str'},
                'num-blocks-per-user': {'type': 'int'},
                'pba-timeout': {'type': 'int'},
                'permit-any-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'source-endip': {'type': 'str'},
                'source-startip': {'type': 'str'},
                'startip': {'type': 'str'},
                'type': {'choices': ['overload', 'one-to-one', 'fixed-port-range', 'port-block-allocation', 'cgn-resource-allocation'], 'type': 'str'},
                'cgn-block-size': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'int'},
                'cgn-client-endip': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'str'},
                'cgn-client-startip': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'str'},
                'cgn-fixedalloc': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-overload': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-port-end': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'int'},
                'cgn-port-start': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'int'},
                'cgn-spa': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'utilization-alarm-clear': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'int'},
                'utilization-alarm-raise': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'int'},
                'endport': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'port-per-user': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'startport': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'add-nat64-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-client-ipv6shift': {'v_range': [['6.2.9', '6.2.12'], ['6.4.7', '6.4.14'], ['7.0.2', '']], 'type': 'int'},
                'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'subnet-broadcast-in-ippool': {'v_range': [['7.0.5', '7.0.12'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'exclude-ip': {'v_range': [['7.2.2', '']], 'type': 'raw'},
                'pba-interim-log': {'v_range': [['7.4.3', '']], 'type': 'int'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ippool_dynamicmapping'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
