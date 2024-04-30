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
module: fmgr_firewall_address6
short_description: Configure IPv6 firewall addresses.
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
    firewall_address6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cache-ttl:
                type: int
                description: Deprecated, please rename it to cache_ttl. Minimal TTL of individual IPv6 addresses in FQDN cache.
            color:
                type: int
                description: Integer value to determine the color of the icon in the GUI
            comment:
                type: str
                description: Comment.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic_Mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: _Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    cache-ttl:
                        type: int
                        description: Deprecated, please rename it to cache_ttl. Minimal TTL of individual IPv6 addresses in FQDN cache.
                    color:
                        type: int
                        description: Integer value to determine the color of the icon in the GUI
                    comment:
                        type: str
                        description: Comment.
                    end-ip:
                        type: str
                        description: Deprecated, please rename it to end_ip. Final IP address
                    fqdn:
                        type: str
                        description: Fully qualified domain name.
                    host:
                        type: str
                        description: Host Address.
                    host-type:
                        type: str
                        description: Deprecated, please rename it to host_type. Host type.
                        choices:
                            - 'any'
                            - 'specific'
                    ip6:
                        type: str
                        description: IPv6 address prefix
                    obj-id:
                        type: str
                        description: Deprecated, please rename it to obj_id. Object ID for NSX.
                    sdn:
                        type: str
                        description: SDN.
                        choices:
                            - 'nsx'
                    start-ip:
                        type: str
                        description: Deprecated, please rename it to start_ip. First IP address
                    tags:
                        type: raw
                        description: (list or str) Tags.
                    template:
                        type: str
                        description: IPv6 address template.
                    type:
                        type: str
                        description: Type of IPv6 address object
                        choices:
                            - 'ipprefix'
                            - 'iprange'
                            - 'nsx'
                            - 'dynamic'
                            - 'fqdn'
                            - 'template'
                            - 'mac'
                            - 'geography'
                            - 'route-tag'
                    uuid:
                        type: str
                        description: Universally Unique Identifier
                    visibility:
                        type: str
                        description: Enable/disable the visibility of the object in the GUI.
                        choices:
                            - 'disable'
                            - 'enable'
                    subnet-segment:
                        type: list
                        elements: dict
                        description: Deprecated, please rename it to subnet_segment. Subnet-Segment.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            type:
                                type: str
                                description: Subnet segment type.
                                choices:
                                    - 'any'
                                    - 'specific'
                            value:
                                type: str
                                description: Subnet segment value.
                    _image-base64:
                        type: str
                        description: Deprecated, please rename it to _image_base64. _Image-Base64.
                    end-mac:
                        type: str
                        description: Deprecated, please rename it to end_mac. Last MAC address in the range.
                    start-mac:
                        type: str
                        description: Deprecated, please rename it to start_mac. First MAC address in the range.
                    country:
                        type: str
                        description: Country.
                    global-object:
                        type: int
                        description: Deprecated, please rename it to global_object. Global-Object.
                    fabric-object:
                        type: str
                        description: Deprecated, please rename it to fabric_object. Security Fabric global object setting.
                        choices:
                            - 'disable'
                            - 'enable'
                    macaddr:
                        type: raw
                        description: (list) Macaddr.
                    epg-name:
                        type: str
                        description: Deprecated, please rename it to epg_name. Endpoint group name.
                    sdn-tag:
                        type: str
                        description: Deprecated, please rename it to sdn_tag. SDN Tag.
                    tenant:
                        type: str
                        description: Tenant.
                    route-tag:
                        type: int
                        description: Deprecated, please rename it to route_tag. Route-tag address.
            end-ip:
                type: str
                description: Deprecated, please rename it to end_ip. Final IP address
            fqdn:
                type: str
                description: Fully qualified domain name.
            host:
                type: str
                description: Host Address.
            host-type:
                type: str
                description: Deprecated, please rename it to host_type. Host type.
                choices:
                    - 'any'
                    - 'specific'
            ip6:
                type: str
                description: IPv6 address prefix
            list:
                type: list
                elements: dict
                description: List.
                suboptions:
                    ip:
                        type: str
                        description: IP.
                    net-id:
                        type: str
                        description: Deprecated, please rename it to net_id. Network ID.
                    obj-id:
                        type: str
                        description: Deprecated, please rename it to obj_id. Object ID.
            name:
                type: str
                description: Address name.
                required: true
            obj-id:
                type: str
                description: Deprecated, please rename it to obj_id. Object ID for NSX.
            sdn:
                type: str
                description: SDN.
                choices:
                    - 'nsx'
            start-ip:
                type: str
                description: Deprecated, please rename it to start_ip. First IP address
            subnet-segment:
                type: list
                elements: dict
                description: Deprecated, please rename it to subnet_segment. Subnet-Segment.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    type:
                        type: str
                        description: Subnet segment type.
                        choices:
                            - 'any'
                            - 'specific'
                    value:
                        type: str
                        description: Subnet segment value.
            tagging:
                type: list
                elements: dict
                description: Tagging.
                suboptions:
                    category:
                        type: str
                        description: Tag category.
                    name:
                        type: str
                        description: Tagging entry name.
                    tags:
                        type: raw
                        description: (list) Tags.
            template:
                type: str
                description: IPv6 address template.
            type:
                type: str
                description: Type of IPv6 address object
                choices:
                    - 'ipprefix'
                    - 'iprange'
                    - 'nsx'
                    - 'dynamic'
                    - 'fqdn'
                    - 'template'
                    - 'mac'
                    - 'geography'
                    - 'route-tag'
            uuid:
                type: str
                description: Universally Unique Identifier
            visibility:
                type: str
                description: Enable/disable the visibility of the object in the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: Names of object-tags applied to address.
            profile-list:
                type: list
                elements: dict
                description: Deprecated, please rename it to profile_list.
                suboptions:
                    profile-id:
                        type: int
                        description: Deprecated, please rename it to profile_id. NSX service profile ID.
            _image-base64:
                type: str
                description: Deprecated, please rename it to _image_base64. _Image-Base64.
            end-mac:
                type: str
                description: Deprecated, please rename it to end_mac. Last MAC address in the range.
            start-mac:
                type: str
                description: Deprecated, please rename it to start_mac. First MAC address in the range.
            country:
                type: str
                description: IPv6 addresses associated to a specific country.
            global-object:
                type: int
                description: Deprecated, please rename it to global_object. Global Object.
            fabric-object:
                type: str
                description: Deprecated, please rename it to fabric_object. Security Fabric global object setting.
                choices:
                    - 'disable'
                    - 'enable'
            macaddr:
                type: raw
                description: (list) Multiple MAC address ranges.
            epg-name:
                type: str
                description: Deprecated, please rename it to epg_name. Endpoint group name.
            sdn-tag:
                type: str
                description: Deprecated, please rename it to sdn_tag. SDN Tag.
            tenant:
                type: str
                description: Tenant.
            route-tag:
                type: int
                description: Deprecated, please rename it to route_tag. Route-tag address.
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
    - name: Configure IPv6 firewall addresses.
      fortinet.fortimanager.fmgr_firewall_address6:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_address6:
          host-type: any # <value in [any, specific]>
          ip6: "::/55"
          name: "ansible-test"
          visibility: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv6 addresses
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_address6"
          params:
            adom: "ansible"
            address6: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/address6',
        '/pm/config/global/obj/firewall/address6'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/address6/{address6}',
        '/pm/config/global/obj/firewall/address6/{address6}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'firewall_address6': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'cache-ttl': {'type': 'int'},
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'cache-ttl': {'type': 'int'},
                        'color': {'type': 'int'},
                        'comment': {'type': 'str'},
                        'end-ip': {'type': 'str'},
                        'fqdn': {'type': 'str'},
                        'host': {'type': 'str'},
                        'host-type': {'choices': ['any', 'specific'], 'type': 'str'},
                        'ip6': {'type': 'str'},
                        'obj-id': {'type': 'str'},
                        'sdn': {'choices': ['nsx'], 'type': 'str'},
                        'start-ip': {'type': 'str'},
                        'tags': {'type': 'raw'},
                        'template': {'type': 'str'},
                        'type': {'choices': ['ipprefix', 'iprange', 'nsx', 'dynamic', 'fqdn', 'template', 'mac', 'geography', 'route-tag'], 'type': 'str'},
                        'uuid': {'type': 'str'},
                        'visibility': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'subnet-segment': {
                            'v_range': [['6.2.1', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['6.2.1', '']], 'type': 'str'},
                                'type': {'v_range': [['6.2.1', '']], 'choices': ['any', 'specific'], 'type': 'str'},
                                'value': {'v_range': [['6.2.1', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        '_image-base64': {'v_range': [['6.2.2', '']], 'type': 'str'},
                        'end-mac': {'v_range': [['6.2.5', '6.2.12'], ['6.4.1', '']], 'type': 'str'},
                        'start-mac': {'v_range': [['6.2.5', '6.2.12'], ['6.4.1', '']], 'type': 'str'},
                        'country': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'global-object': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'fabric-object': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'macaddr': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                        'epg-name': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'sdn-tag': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'tenant': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'route-tag': {'v_range': [['7.4.0', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'end-ip': {'type': 'str'},
                'fqdn': {'type': 'str'},
                'host': {'type': 'str'},
                'host-type': {'choices': ['any', 'specific'], 'type': 'str'},
                'ip6': {'type': 'str'},
                'list': {
                    'type': 'list',
                    'options': {
                        'ip': {'type': 'str'},
                        'net-id': {'v_range': [['6.2.1', '']], 'type': 'str'},
                        'obj-id': {'v_range': [['6.2.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'},
                'obj-id': {'type': 'str'},
                'sdn': {'choices': ['nsx'], 'type': 'str'},
                'start-ip': {'type': 'str'},
                'subnet-segment': {
                    'type': 'list',
                    'options': {'name': {'type': 'str'}, 'type': {'choices': ['any', 'specific'], 'type': 'str'}, 'value': {'type': 'str'}},
                    'elements': 'dict'
                },
                'tagging': {
                    'type': 'list',
                    'options': {'category': {'type': 'str'}, 'name': {'type': 'str'}, 'tags': {'type': 'raw'}},
                    'elements': 'dict'
                },
                'template': {'type': 'str'},
                'type': {'choices': ['ipprefix', 'iprange', 'nsx', 'dynamic', 'fqdn', 'template', 'mac', 'geography', 'route-tag'], 'type': 'str'},
                'uuid': {'type': 'str'},
                'visibility': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.2.0', '6.4.14']], 'type': 'str'},
                'profile-list': {
                    'v_range': [['6.2.0', '6.2.12']],
                    'type': 'list',
                    'options': {'profile-id': {'v_range': [['6.2.0', '6.2.12']], 'type': 'int'}},
                    'elements': 'dict'
                },
                '_image-base64': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'end-mac': {'v_range': [['6.2.5', '6.2.12'], ['6.4.1', '']], 'type': 'str'},
                'start-mac': {'v_range': [['6.2.5', '6.2.12'], ['6.4.1', '']], 'type': 'str'},
                'country': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'global-object': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'fabric-object': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'macaddr': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'epg-name': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'sdn-tag': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'tenant': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'route-tag': {'v_range': [['7.4.0', '']], 'type': 'int'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_address6'),
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
