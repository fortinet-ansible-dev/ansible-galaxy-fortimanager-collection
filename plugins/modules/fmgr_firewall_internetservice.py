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
module: fmgr_firewall_internetservice
short_description: Show Internet Service application.
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
    firewall_internetservice:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            database:
                type: str
                description: Database.
                choices:
                    - 'isdb'
                    - 'irdb'
            direction:
                type: str
                description: Direction.
                choices:
                    - 'src'
                    - 'dst'
                    - 'both'
            entry:
                type: list
                elements: dict
                description: Entry.
                suboptions:
                    id:
                        type: int
                        description: Entry ID.
                    ip_number:
                        aliases: ['ip-number']
                        type: int
                        description: Total number of IP addresses.
                    ip_range_number:
                        aliases: ['ip-range-number']
                        type: int
                        description: Total number of IP ranges.
                    port:
                        type: raw
                        description: (list) Integer value for the TCP/IP port
                    protocol:
                        type: int
                        description: Integer value for the protocol type as defined by IANA
            icon_id:
                aliases: ['icon-id']
                type: int
                description: Icon id.
            id:
                type: int
                description: Id.
            name:
                type: str
                description: Name.
            offset:
                type: int
                description: Offset.
            reputation:
                type: int
                description: Reputation.
            sld_id:
                aliases: ['sld-id']
                type: int
                description: Sld id.
            extra_ip_range_number:
                aliases: ['extra-ip-range-number']
                type: int
                description: Extra ip range number.
            ip_number:
                aliases: ['ip-number']
                type: int
                description: Ip number.
            ip_range_number:
                aliases: ['ip-range-number']
                type: int
                description: Ip range number.
            jitter_threshold:
                aliases: ['jitter-threshold']
                type: int
                description: Jitter threshold.
            latency_threshold:
                aliases: ['latency-threshold']
                type: int
                description: Latency threshold.
            obsolete:
                type: int
                description: Obsolete.
            packetloss_threshold:
                aliases: ['packetloss-threshold']
                type: int
                description: Packetloss threshold.
            singularity:
                type: int
                description: Singularity.
            city:
                type: raw
                description: (list) City sequence number list.
            country:
                type: raw
                description: (list) Country sequence number list.
            region:
                type: raw
                description: (list) Region sequence number list.
            city6:
                type: raw
                description: (list) IPv6 City sequence number list.
            country6:
                type: raw
                description: (list) IPv6 Country sequence number list.
            extra_ip6_range_number:
                aliases: ['extra-ip6-range-number']
                type: int
                description: Extra ip6 range number.
            ip6_range_number:
                aliases: ['ip6-range-number']
                type: int
                description: Ip6 range number.
            region6:
                type: raw
                description: (list) IPv6 Region sequence number list.
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
    - name: Show Internet Service application.
      fortinet.fortimanager.fmgr_firewall_internetservice:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        firewall_internetservice:
          # database: <value in [isdb, irdb]>
          # direction: <value in [src, dst, both]>
          # entry:
          #   - id: <integer>
          #     ip_number: <integer>
          #     ip_range_number: <integer>
          #     port: <list or integer>
          #     protocol: <integer>
          # icon_id: <integer>
          # id: <integer>
          # name: <string>
          # offset: <integer>
          # reputation: <integer>
          # sld_id: <integer>
          # extra_ip_range_number: <integer>
          # ip_number: <integer>
          # ip_range_number: <integer>
          # jitter_threshold: <integer>
          # latency_threshold: <integer>
          # obsolete: <integer>
          # packetloss_threshold: <integer>
          # singularity: <integer>
          # city: <list or integer>
          # country: <list or integer>
          # region: <list or integer>
          # city6: <list or integer>
          # country6: <list or integer>
          # extra_ip6_range_number: <integer>
          # ip6_range_number: <integer>
          # region6: <list or integer>
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
        '/pm/config/adom/{adom}/obj/firewall/internet-service',
        '/pm/config/global/obj/firewall/internet-service'
    ]
    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'firewall_internetservice': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'database': {'choices': ['isdb', 'irdb'], 'type': 'str'},
                'direction': {'choices': ['src', 'dst', 'both'], 'type': 'str'},
                'entry': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        'ip-number': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        'ip-range-number': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        'port': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
                        'protocol': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'icon-id': {'type': 'int'},
                'id': {'type': 'int'},
                'name': {'type': 'str'},
                'offset': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                'reputation': {'type': 'int'},
                'sld-id': {'type': 'int'},
                'extra-ip-range-number': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'ip-number': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'ip-range-number': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'jitter-threshold': {'v_range': [['6.2.0', '7.2.0']], 'type': 'int'},
                'latency-threshold': {'v_range': [['6.2.0', '7.2.0']], 'type': 'int'},
                'obsolete': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'packetloss-threshold': {'v_range': [['6.2.0', '7.2.0']], 'type': 'int'},
                'singularity': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'city': {'v_range': [['6.4.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'country': {'v_range': [['6.4.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'region': {'v_range': [['6.4.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'city6': {'v_range': [['7.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'country6': {'v_range': [['7.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'extra-ip6-range-number': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'ip6-range-number': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'region6': {'v_range': [['7.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetservice'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
