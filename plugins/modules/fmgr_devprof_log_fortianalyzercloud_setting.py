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
module: fmgr_devprof_log_fortianalyzercloud_setting
short_description: Global FortiAnalyzer Cloud settings.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_log_fortianalyzercloud_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            __change_ip:
                type: int
                description: Hidden attribute.
            access-config:
                type: str
                description: Deprecated, please rename it to access_config. Enable/disable FortiAnalyzer access to configuration and data.
                choices:
                    - 'disable'
                    - 'enable'
            certificate:
                type: str
                description: Certificate used to communicate with FortiAnalyzer.
            conn-timeout:
                type: int
                description: Deprecated, please rename it to conn_timeout. FortiAnalyzer connection time-out in seconds
            enc-algorithm:
                type: str
                description: Deprecated, please rename it to enc_algorithm. Configure the level of SSL protection for secure communication with FortiAn...
                choices:
                    - 'high'
                    - 'low'
                    - 'high-medium'
                    - 'low-medium'
            hmac-algorithm:
                type: str
                description: Deprecated, please rename it to hmac_algorithm. FortiAnalyzer IPsec tunnel HMAC algorithm.
                choices:
                    - 'sha256'
                    - 'sha1'
            ips-archive:
                type: str
                description: Deprecated, please rename it to ips_archive. Enable/disable IPS packet archive logging.
                choices:
                    - 'disable'
                    - 'enable'
            monitor-failure-retry-period:
                type: int
                description: Deprecated, please rename it to monitor_failure_retry_period. Time between FortiAnalyzer connection retries in seconds
            monitor-keepalive-period:
                type: int
                description: Deprecated, please rename it to monitor_keepalive_period. Time between OFTP keepalives in seconds
            source-ip:
                type: str
                description: Deprecated, please rename it to source_ip. Source IPv4 or IPv6 address used to communicate with FortiAnalyzer.
            ssl-min-proto-version:
                type: str
                description: Deprecated, please rename it to ssl_min_proto_version. Minimum supported protocol version for SSL/TLS connections
                choices:
                    - 'default'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-3'
            status:
                type: str
                description: Enable/disable logging to FortiAnalyzer.
                choices:
                    - 'disable'
                    - 'enable'
            upload-day:
                type: str
                description: Deprecated, please rename it to upload_day. Day of week
            upload-interval:
                type: str
                description: Deprecated, please rename it to upload_interval. Frequency to upload log files to FortiAnalyzer.
                choices:
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
            upload-option:
                type: str
                description: Deprecated, please rename it to upload_option. Enable/disable logging to hard disk and then uploading to FortiAnalyzer.
                choices:
                    - 'store-and-upload'
                    - 'realtime'
                    - '1-minute'
                    - '5-minute'
            upload-time:
                type: str
                description: Deprecated, please rename it to upload_time. Time to upload logs
            max-log-rate:
                type: int
                description: Deprecated, please rename it to max_log_rate. FortiAnalyzer maximum log rate in MBps
            priority:
                type: str
                description: Set log transmission priority.
                choices:
                    - 'low'
                    - 'default'
            interface:
                type: str
                description: Specify outgoing interface to reach server.
            interface-select-method:
                type: str
                description: Deprecated, please rename it to interface_select_method. Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            preshared-key:
                type: str
                description: Deprecated, please rename it to preshared_key. Preshared-key used for auto-authorization on FortiAnalyzer.
            certificate-verification:
                type: str
                description: Deprecated, please rename it to certificate_verification. Enable/disable identity verification of FortiAnalyzer by use of ...
                choices:
                    - 'disable'
                    - 'enable'
            serial:
                type: raw
                description: (list) No description.
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
    - name: Global FortiAnalyzer Cloud settings.
      fortinet.fortimanager.fmgr_devprof_log_fortianalyzercloud_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        devprof: <your own value>
        devprof_log_fortianalyzercloud_setting:
          __change_ip: <integer>
          access_config: <value in [disable, enable]>
          certificate: <string>
          conn_timeout: <integer>
          enc_algorithm: <value in [high, low, high-medium, ...]>
          hmac_algorithm: <value in [sha256, sha1]>
          ips_archive: <value in [disable, enable]>
          monitor_failure_retry_period: <integer>
          monitor_keepalive_period: <integer>
          source_ip: <string>
          ssl_min_proto_version: <value in [default, TLSv1-1, TLSv1-2, ...]>
          status: <value in [disable, enable]>
          upload_day: <string>
          upload_interval: <value in [daily, weekly, monthly]>
          upload_option: <value in [store-and-upload, realtime, 1-minute, ...]>
          upload_time: <string>
          max_log_rate: <integer>
          priority: <value in [low, default]>
          interface: <string>
          interface_select_method: <value in [auto, sdwan, specify]>
          preshared_key: <string>
          certificate_verification: <value in [disable, enable]>
          serial: <list or string>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/log/fortianalyzer-cloud/setting'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/devprof/{devprof}/log/fortianalyzer-cloud/setting/{setting}'
    ]

    url_params = ['adom', 'devprof']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_log_fortianalyzercloud_setting': {
            'type': 'dict',
            'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                '__change_ip': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'access-config': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'certificate': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'conn-timeout': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'enc-algorithm': {
                    'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['high', 'low', 'high-medium', 'low-medium'],
                    'type': 'str'
                },
                'hmac-algorithm': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['sha256', 'sha1'], 'type': 'str'},
                'ips-archive': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'monitor-failure-retry-period': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'monitor-keepalive-period': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'source-ip': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['default', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3'],
                    'type': 'str'
                },
                'status': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'upload-day': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'upload-interval': {
                    'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['daily', 'weekly', 'monthly'],
                    'type': 'str'
                },
                'upload-option': {
                    'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['store-and-upload', 'realtime', '1-minute', '5-minute'],
                    'type': 'str'
                },
                'upload-time': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'max-log-rate': {'v_range': [['6.2.2', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'priority': {'v_range': [['6.2.2', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['low', 'default'], 'type': 'str'},
                'interface': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'str'},
                'interface-select-method': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'preshared-key': {'v_range': [['7.0.0', '']], 'no_log': True, 'type': 'str'},
                'certificate-verification': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'serial': {'v_range': [['7.0.3', '']], 'type': 'raw'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_log_fortianalyzercloud_setting'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
