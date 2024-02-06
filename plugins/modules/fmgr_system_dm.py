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
module: fmgr_system_dm
short_description: Configure dm.
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
    system_dm:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            concurrent-install-image-limit:
                type: int
                description: Deprecated, please rename it to concurrent_install_image_limit. Maximum number of concurrent install image
            concurrent-install-limit:
                type: int
                description: Deprecated, please rename it to concurrent_install_limit. Maximum number of concurrent installs
            concurrent-install-script-limit:
                type: int
                description: Deprecated, please rename it to concurrent_install_script_limit. Maximum number of concurrent install scripts
            discover-timeout:
                type: int
                description: Deprecated, please rename it to discover_timeout. Check connection timeout when discover device
            dpm-logsize:
                type: int
                description: Deprecated, please rename it to dpm_logsize. Maximum dpm log size per device
            fgfm-sock-timeout:
                type: int
                description: Deprecated, please rename it to fgfm_sock_timeout. Maximum FGFM socket idle time
            fgfm_keepalive_itvl:
                type: int
                description: FGFM protocol keep alive interval
            force-remote-diff:
                type: str
                description:
                    - Deprecated, please rename it to force_remote_diff.
                    - Always use remote diff when installing.
                    - disable - Disable.
                    - enable - Enable.
                choices:
                    - 'disable'
                    - 'enable'
            fortiap-refresh-cnt:
                type: int
                description: Deprecated, please rename it to fortiap_refresh_cnt. Max auto refresh FortiAP number each time
            fortiap-refresh-itvl:
                type: int
                description: Deprecated, please rename it to fortiap_refresh_itvl. Auto refresh FortiAP status interval
            fortiext-refresh-cnt:
                type: int
                description: Deprecated, please rename it to fortiext_refresh_cnt. Max device number for FortiExtender auto refresh
            install-image-timeout:
                type: int
                description: Deprecated, please rename it to install_image_timeout. Maximum waiting time for image transfer and device upgrade
            install-tunnel-retry-itvl:
                type: int
                description: Deprecated, please rename it to install_tunnel_retry_itvl. Time to re-establish tunnel during install
            max-revs:
                type: int
                description: Deprecated, please rename it to max_revs. Maximum number of revisions saved
            nr-retry:
                type: int
                description: Deprecated, please rename it to nr_retry. Number of retries.
            retry:
                type: str
                description:
                    - Enable/disable configuration install retry.
                    - disable - Disable.
                    - enable - Enable.
                choices:
                    - 'disable'
                    - 'enable'
            retry-intvl:
                type: int
                description: Deprecated, please rename it to retry_intvl. Retry interval.
            rollback-allow-reboot:
                type: str
                description:
                    - Deprecated, please rename it to rollback_allow_reboot.
                    - Enable/disable FortiGate reboot to rollback when installing script/config.
                    - disable - Disable.
                    - enable - Enable.
                choices:
                    - 'disable'
                    - 'enable'
            script-logsize:
                type: int
                description: Deprecated, please rename it to script_logsize. Maximum script log size per device
            skip-scep-check:
                type: str
                description:
                    - Deprecated, please rename it to skip_scep_check.
                    - Enable/disable installing scep related objects even if scep url is configured.
                    - disable - Disable.
                    - enable - Enable.
                choices:
                    - 'disable'
                    - 'enable'
            skip-tunnel-fcp-req:
                type: str
                description:
                    - Deprecated, please rename it to skip_tunnel_fcp_req.
                    - Enable/disable skip the fcp request sent from fgfm tunnel
                    - disable - Disable.
                    - enable - Enable.
                choices:
                    - 'disable'
                    - 'enable'
            verify-install:
                type: str
                description:
                    - Deprecated, please rename it to verify_install.
                    - Verify install against remote configuration.
                    - disable - Disable.
                    - optimal - Verify installation for command errors.
                    - enable - Always verify installation.
                choices:
                    - 'disable'
                    - 'optimal'
                    - 'enable'
            fgfm-install-refresh-count:
                type: int
                description: Deprecated, please rename it to fgfm_install_refresh_count. Maximum FGFM install refresh attempt.
            conf-merge-after-script:
                type: str
                description:
                    - Deprecated, please rename it to conf_merge_after_script.
                    - Merge config after run script on remote device, instead of full retrieve.
                    - disable - Disable.
                    - enable - Enable.
                choices:
                    - 'disable'
                    - 'enable'
            log-autoupdate:
                type: str
                description:
                    - Deprecated, please rename it to log_autoupdate.
                    - Enable/disable autoupdate debug logging.
                    - disable - Disable.
                    - enable - Enable.
                choices:
                    - 'disable'
                    - 'enable'
            fgfm-auto-retrieve-timeout:
                type: int
                description: Deprecated, please rename it to fgfm_auto_retrieve_timeout. Maximum waiting time for auto retrieve
            install-fds-timeout:
                type: int
                description: Deprecated, please rename it to install_fds_timeout. Maximum waiting time for fgt update during install
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
    - name: Configure dm.
      fortinet.fortimanager.fmgr_system_dm:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_dm:
          concurrent_install_image_limit: <integer>
          concurrent_install_limit: <integer>
          concurrent_install_script_limit: <integer>
          discover_timeout: <integer>
          dpm_logsize: <integer>
          fgfm_sock_timeout: <integer>
          fgfm_keepalive_itvl: <integer>
          force_remote_diff: <value in [disable, enable]>
          fortiap_refresh_cnt: <integer>
          fortiap_refresh_itvl: <integer>
          fortiext_refresh_cnt: <integer>
          install_image_timeout: <integer>
          install_tunnel_retry_itvl: <integer>
          max_revs: <integer>
          nr_retry: <integer>
          retry: <value in [disable, enable]>
          retry_intvl: <integer>
          rollback_allow_reboot: <value in [disable, enable]>
          script_logsize: <integer>
          skip_scep_check: <value in [disable, enable]>
          skip_tunnel_fcp_req: <value in [disable, enable]>
          verify_install: <value in [disable, optimal, enable]>
          fgfm_install_refresh_count: <integer>
          conf_merge_after_script: <value in [disable, enable]>
          log_autoupdate: <value in [disable, enable]>
          fgfm_auto_retrieve_timeout: <integer>
          install_fds_timeout: <integer>
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
        '/cli/global/system/dm'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/dm/{dm}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_dm': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'concurrent-install-image-limit': {'type': 'int'},
                'concurrent-install-limit': {'type': 'int'},
                'concurrent-install-script-limit': {'type': 'int'},
                'discover-timeout': {'type': 'int'},
                'dpm-logsize': {'type': 'int'},
                'fgfm-sock-timeout': {'type': 'int'},
                'fgfm_keepalive_itvl': {'type': 'int'},
                'force-remote-diff': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiap-refresh-cnt': {'type': 'int'},
                'fortiap-refresh-itvl': {'type': 'int'},
                'fortiext-refresh-cnt': {'type': 'int'},
                'install-image-timeout': {'type': 'int'},
                'install-tunnel-retry-itvl': {'type': 'int'},
                'max-revs': {'type': 'int'},
                'nr-retry': {'type': 'int'},
                'retry': {'choices': ['disable', 'enable'], 'type': 'str'},
                'retry-intvl': {'type': 'int'},
                'rollback-allow-reboot': {'choices': ['disable', 'enable'], 'type': 'str'},
                'script-logsize': {'type': 'int'},
                'skip-scep-check': {'choices': ['disable', 'enable'], 'type': 'str'},
                'skip-tunnel-fcp-req': {'choices': ['disable', 'enable'], 'type': 'str'},
                'verify-install': {'choices': ['disable', 'optimal', 'enable'], 'type': 'str'},
                'fgfm-install-refresh-count': {'v_range': [['6.2.5', '']], 'type': 'int'},
                'conf-merge-after-script': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-autoupdate': {
                    'v_range': [['6.4.12', '6.4.13'], ['7.0.9', '7.0.10'], ['7.2.4', '7.2.4'], ['7.4.1', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'fgfm-auto-retrieve-timeout': {'v_range': [['6.4.13', '6.4.13'], ['7.0.9', '7.0.10'], ['7.2.4', '7.2.4'], ['7.4.1', '']], 'type': 'int'},
                'install-fds-timeout': {'v_range': [['7.4.1', '']], 'type': 'int'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dm'),
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
