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
module: fmgr_pkg_header_shapingpolicy
short_description: Configure shaping policies.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_header_shapingpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app-category:
                type: raw
                description: (list or str) Deprecated, please rename it to app_category.
            app-group:
                type: raw
                description: (list or str) Deprecated, please rename it to app_group.
            application:
                type: raw
                description: (list) No description.
            class-id:
                type: raw
                description: (int or str) Deprecated, please rename it to class_id.
            comment:
                type: str
                description: No description.
            diffserv-forward:
                type: str
                description: Deprecated, please rename it to diffserv_forward.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv-reverse:
                type: str
                description: Deprecated, please rename it to diffserv_reverse.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode-forward:
                type: str
                description: Deprecated, please rename it to diffservcode_forward.
            diffservcode-rev:
                type: str
                description: Deprecated, please rename it to diffservcode_rev.
            dstaddr:
                type: raw
                description: (list or str) No description.
            dstaddr6:
                type: raw
                description: (list or str) No description.
            dstintf:
                type: raw
                description: (list or str) No description.
            groups:
                type: raw
                description: (list or str) No description.
            id:
                type: int
                description: No description.
                required: true
            internet-service:
                type: str
                description: Deprecated, please rename it to internet_service.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-custom:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_custom.
            internet-service-custom-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_custom_group.
            internet-service-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_group.
            internet-service-id:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_id.
            internet-service-src:
                type: str
                description: Deprecated, please rename it to internet_service_src.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src-custom:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_custom.
            internet-service-src-custom-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_custom_group.
            internet-service-src-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_group.
            internet-service-src-id:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_id.
            ip-version:
                type: str
                description: Deprecated, please rename it to ip_version.
                choices:
                    - '4'
                    - '6'
            per-ip-shaper:
                type: str
                description: Deprecated, please rename it to per_ip_shaper.
            schedule:
                type: str
                description: No description.
            service:
                type: raw
                description: (list or str) No description.
            srcaddr:
                type: raw
                description: (list or str) No description.
            srcaddr6:
                type: raw
                description: (list or str) No description.
            srcintf:
                type: raw
                description: (list or str) No description.
            status:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            tos:
                type: str
                description: No description.
            tos-mask:
                type: str
                description: Deprecated, please rename it to tos_mask.
            tos-negate:
                type: str
                description: Deprecated, please rename it to tos_negate.
                choices:
                    - 'disable'
                    - 'enable'
            traffic-shaper:
                type: str
                description: Deprecated, please rename it to traffic_shaper.
            traffic-shaper-reverse:
                type: str
                description: Deprecated, please rename it to traffic_shaper_reverse.
            url-category:
                type: raw
                description: (list or str) Deprecated, please rename it to url_category.
            users:
                type: raw
                description: (list or str) No description.
            uuid:
                type: str
                description: No description.
            internet-service-name:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_name.
            internet-service-src-name:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_name.
            class-id-reverse:
                type: int
                description: Deprecated, please rename it to class_id_reverse.
            service-type:
                type: str
                description: Deprecated, please rename it to service_type.
                choices:
                    - 'service'
                    - 'internet-service'
            uuid-idx:
                type: int
                description: Deprecated, please rename it to uuid_idx.
            cos:
                type: str
                description: VLAN CoS bit pattern.
            cos-mask:
                type: str
                description: Deprecated, please rename it to cos_mask. VLAN CoS evaluated bits.
            traffic-type:
                type: str
                description: Deprecated, please rename it to traffic_type. Traffic type.
                choices:
                    - 'forwarding'
                    - 'local-in'
                    - 'local-out'
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
    - name: Configure shaping policies.
      fortinet.fortimanager.fmgr_pkg_header_shapingpolicy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_header_shapingpolicy:
          app_category: <list or string>
          app_group: <list or string>
          application: <list or integer>
          class_id: <integer or string>
          comment: <string>
          diffserv_forward: <value in [disable, enable]>
          diffserv_reverse: <value in [disable, enable]>
          diffservcode_forward: <string>
          diffservcode_rev: <string>
          dstaddr: <list or string>
          dstaddr6: <list or string>
          dstintf: <list or string>
          groups: <list or string>
          id: <integer>
          internet_service: <value in [disable, enable]>
          internet_service_custom: <list or string>
          internet_service_custom_group: <list or string>
          internet_service_group: <list or string>
          internet_service_id: <list or string>
          internet_service_src: <value in [disable, enable]>
          internet_service_src_custom: <list or string>
          internet_service_src_custom_group: <list or string>
          internet_service_src_group: <list or string>
          internet_service_src_id: <list or string>
          ip_version: <value in [4, 6]>
          per_ip_shaper: <string>
          schedule: <string>
          service: <list or string>
          srcaddr: <list or string>
          srcaddr6: <list or string>
          srcintf: <list or string>
          status: <value in [disable, enable]>
          tos: <string>
          tos_mask: <string>
          tos_negate: <value in [disable, enable]>
          traffic_shaper: <string>
          traffic_shaper_reverse: <string>
          url_category: <list or string>
          users: <list or string>
          uuid: <string>
          internet_service_name: <list or string>
          internet_service_src_name: <list or string>
          class_id_reverse: <integer>
          service_type: <value in [service, internet-service]>
          uuid_idx: <integer>
          cos: <string>
          cos_mask: <string>
          traffic_type: <value in [forwarding, local-in, local-out]>
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
        '/pm/config/global/pkg/{pkg}/global/header/shaping-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/pkg/{pkg}/global/header/shaping-policy/{shaping-policy}'
    ]

    url_params = ['pkg']
    module_primary_key = 'id'
    module_arg_spec = {
        'pkg': {'required': True, 'type': 'str'},
        'pkg_header_shapingpolicy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'app-category': {'type': 'raw'},
                'app-group': {'type': 'raw'},
                'application': {'type': 'raw'},
                'class-id': {'type': 'raw'},
                'comment': {'type': 'str'},
                'diffserv-forward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'type': 'str'},
                'diffservcode-rev': {'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'dstaddr6': {'type': 'raw'},
                'dstintf': {'type': 'raw'},
                'groups': {'type': 'raw'},
                'id': {'required': True, 'type': 'int'},
                'internet-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'type': 'raw'},
                'internet-service-custom-group': {'type': 'raw'},
                'internet-service-group': {'type': 'raw'},
                'internet-service-id': {'type': 'raw'},
                'internet-service-src': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'type': 'raw'},
                'internet-service-src-custom-group': {'type': 'raw'},
                'internet-service-src-group': {'type': 'raw'},
                'internet-service-src-id': {'type': 'raw'},
                'ip-version': {'choices': ['4', '6'], 'type': 'str'},
                'per-ip-shaper': {'type': 'str'},
                'schedule': {'type': 'str'},
                'service': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'srcaddr6': {'type': 'raw'},
                'srcintf': {'type': 'raw'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tos': {'type': 'str'},
                'tos-mask': {'type': 'str'},
                'tos-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'type': 'str'},
                'traffic-shaper-reverse': {'type': 'str'},
                'url-category': {'type': 'raw'},
                'users': {'type': 'raw'},
                'uuid': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'internet-service-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'class-id-reverse': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'service-type': {'v_range': [['7.0.3', '']], 'choices': ['service', 'internet-service'], 'type': 'str'},
                'uuid-idx': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'cos': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'cos-mask': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'traffic-type': {'v_range': [['7.4.0', '']], 'choices': ['forwarding', 'local-in', 'local-out'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = [
        {
            'attribute_path': ['pkg_header_shapingpolicy', 'id'],
            'lambda': 'int($) >= 1073741824',
            'fail_action': 'warn',
            'hint_message': 'id should be larger than 2^30, i.e. 1073741824, otherwise it will be ignored.'
        }
    ]

    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_header_shapingpolicy'),
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
