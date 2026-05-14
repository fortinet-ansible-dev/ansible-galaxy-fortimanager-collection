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
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_dm:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            concurrent_install_image_limit:
                aliases: ['concurrent-install-image-limit']
                type: int
                description: Maximum number of concurrent install image
            concurrent_install_limit:
                aliases: ['concurrent-install-limit']
                type: int
                description: Maximum number of concurrent installs
            concurrent_install_script_limit:
                aliases: ['concurrent-install-script-limit']
                type: int
                description: Maximum number of concurrent install scripts
            discover_timeout:
                aliases: ['discover-timeout']
                type: int
                description: Check connection timeout when discover device
            dpm_logsize:
                aliases: ['dpm-logsize']
                type: int
                description: Maximum dpm log size per device
            fgfm_sock_timeout:
                aliases: ['fgfm-sock-timeout']
                type: int
                description: Maximum FGFM socket idle time
            fgfm_keepalive_itvl:
                type: int
                description: FGFM protocol keep alive interval
            force_remote_diff:
                aliases: ['force-remote-diff']
                type: str
                description:
                    - Always use remote diff when installing.
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            fortiap_refresh_cnt:
                aliases: ['fortiap-refresh-cnt']
                type: int
                description: Max auto refresh FortiAP number each time
            fortiap_refresh_itvl:
                aliases: ['fortiap-refresh-itvl']
                type: int
                description: Auto refresh FortiAP status interval
            fortiext_refresh_cnt:
                aliases: ['fortiext-refresh-cnt']
                type: int
                description: Max device number for FortiExtender auto refresh
            install_image_timeout:
                aliases: ['install-image-timeout']
                type: int
                description: Maximum waiting time for image transfer and device upgrade
            install_tunnel_retry_itvl:
                aliases: ['install-tunnel-retry-itvl']
                type: int
                description: Time to re-establish tunnel during install
            max_revs:
                aliases: ['max-revs']
                type: int
                description: Maximum number of revisions saved
            nr_retry:
                aliases: ['nr-retry']
                type: int
                description: Number of retries.
            retry:
                type: str
                description:
                    - Enable/disable configuration install retry.
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            retry_intvl:
                aliases: ['retry-intvl']
                type: int
                description: Retry interval.
            rollback_allow_reboot:
                aliases: ['rollback-allow-reboot']
                type: str
                description:
                    - Enable/disable FortiGate reboot to rollback when installing script/config.
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            script_logsize:
                aliases: ['script-logsize']
                type: int
                description: Maximum script log size per device
            skip_scep_check:
                aliases: ['skip-scep-check']
                type: str
                description:
                    - Enable/disable installing scep related objects even if scep url is configured.
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            skip_tunnel_fcp_req:
                aliases: ['skip-tunnel-fcp-req']
                type: str
                description:
                    - Enable/disable skip the fcp request sent from fgfm tunnel
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            verify_install:
                aliases: ['verify-install']
                type: str
                description:
                    - Verify install against remote configuration.
                    - disable - Disable.
                    - optimal - Verify installation for command errors.
                    - enable - Always verify installation.
                choices: ['disable', 'optimal', 'enable']
            fgfm_install_refresh_count:
                aliases: ['fgfm-install-refresh-count']
                type: int
                description: Maximum FGFM install refresh attempt.
            conf_merge_after_script:
                aliases: ['conf-merge-after-script']
                type: str
                description:
                    - Merge config after run script on remote device, instead of full retrieve.
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            log_autoupdate:
                aliases: ['log-autoupdate']
                type: str
                description:
                    - Enable/disable autoupdate debug logging.
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            fgfm_auto_retrieve_timeout:
                aliases: ['fgfm-auto-retrieve-timeout']
                type: int
                description: Maximum waiting time for auto retrieve
            install_fds_timeout:
                aliases: ['install-fds-timeout']
                type: int
                description: Maximum waiting time for fgt update during install
            handle_nonhasync_config:
                aliases: ['handle-nonhasync-config']
                type: str
                description:
                    - Enable/disable nonhasync config handling.
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            autoupdate_merge_revision:
                aliases: ['autoupdate-merge-revision']
                type: str
                description: Autoupdate merge revision.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure dm.
      fortinet.fortimanager.fmgr_system_dm:
        # workspace_locking_adom: <global or your adom name>
        system_dm:
          # concurrent_install_image_limit: <integer>
          # concurrent_install_limit: <integer>
          # concurrent_install_script_limit: <integer>
          # discover_timeout: <integer>
          # dpm_logsize: <integer>
          # fgfm_sock_timeout: <integer>
          # fgfm_keepalive_itvl: <integer>
          # force_remote_diff: <value in [disable, enable]>
          # fortiap_refresh_cnt: <integer>
          # fortiap_refresh_itvl: <integer>
          # fortiext_refresh_cnt: <integer>
          # install_image_timeout: <integer>
          # install_tunnel_retry_itvl: <integer>
          # max_revs: <integer>
          # nr_retry: <integer>
          # retry: <value in [disable, enable]>
          # retry_intvl: <integer>
          # rollback_allow_reboot: <value in [disable, enable]>
          # script_logsize: <integer>
          # skip_scep_check: <value in [disable, enable]>
          # skip_tunnel_fcp_req: <value in [disable, enable]>
          # verify_install: <value in [disable, optimal, enable]>
          # fgfm_install_refresh_count: <integer>
          # conf_merge_after_script: <value in [disable, enable]>
          # log_autoupdate: <value in [disable, enable]>
          # fgfm_auto_retrieve_timeout: <integer>
          # install_fds_timeout: <integer>
          # handle_nonhasync_config: <value in [disable, enable]>
          # autoupdate_merge_revision: <value in [disable, enable]>
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
        '/cli/global/system/dm'
    ]
    module_arg_spec = {
        'system_dm': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
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
                'conf-merge-after-script': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-autoupdate': {
                    'v_range': [['6.4.12', '6.4.15'], ['7.0.9', '7.0.16'], ['7.2.4', '7.2.12'], ['7.4.1', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'fgfm-auto-retrieve-timeout': {'v_range': [['6.4.13', '6.4.15'], ['7.0.9', '7.0.16'], ['7.2.4', '7.2.12'], ['7.4.1', '']], 'type': 'int'},
                'install-fds-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.1', '']], 'type': 'int'},
                'handle-nonhasync-config': {
                    'v_range': [['7.2.11', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'autoupdate-merge-revision': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dm'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
