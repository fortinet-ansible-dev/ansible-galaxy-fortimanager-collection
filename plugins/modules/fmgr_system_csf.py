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
module: fmgr_system_csf
short_description: Add this device to a Security Fabric or set up a new Security Fabric on this device.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.3.0"
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
    system_csf:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            accept-auth-by-cert:
                type: str
                description:
                    - Deprecated, please rename it to accept_auth_by_cert.
                    - Accept connections with unknown certificates and ask admin for approval.
                    - disable - Do not accept SSL connections with unknown certificates.
                    - enable - Accept SSL connections without automatic certificate verification.
                choices:
                    - 'disable'
                    - 'enable'
            authorization-request-type:
                type: str
                description:
                    - Deprecated, please rename it to authorization_request_type.
                    - Authorization request type.
                    - certificate - Request verification by certificate.
                    - serial - Request verification by serial number.
                choices:
                    - 'certificate'
                    - 'serial'
            certificate:
                type: str
                description: Certificate.
            configuration-sync:
                type: str
                description:
                    - Deprecated, please rename it to configuration_sync.
                    - Configuration sync mode.
                    - default - Synchronize configuration for IPAM, FortiAnalyzer, FortiSandbox, and Central Management to root node.
                    - local - Do not synchronize configuration with root node.
                choices:
                    - 'default'
                    - 'local'
            downstream-access:
                type: str
                description:
                    - Deprecated, please rename it to downstream_access.
                    - Enable/disable downstream device access to this device&apos;s configuration and data.
                    - disable - Disable downstream device access to this device&apos;s configuration and data.
                    - enable - Enable downstream device access to this device&apos;s configuration and data.
                choices:
                    - 'disable'
                    - 'enable'
            downstream-accprofile:
                type: str
                description: Deprecated, please rename it to downstream_accprofile. Default access profile for requests from downstream devices.
            fabric-connector:
                type: list
                elements: dict
                description: Deprecated, please rename it to fabric_connector.
                suboptions:
                    accprofile:
                        type: str
                        description: Override access profile.
                    configuration-write-access:
                        type: str
                        description:
                            - Deprecated, please rename it to configuration_write_access.
                            - Enable/disable downstream device write access to configuration.
                            - disable - Disable downstream device write access to configuration.
                            - enable - Enable downstream device write access to configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    serial:
                        type: str
                        description: Serial.
            fabric-object-unification:
                type: str
                description:
                    - Deprecated, please rename it to fabric_object_unification.
                    - Fabric CMDB Object Unification.
                    - local - Global CMDB objects will not be synchronized to and from this device.
                    - default - Global CMDB objects will be synchronized in Security Fabric.
                choices:
                    - 'local'
                    - 'default'
            fabric-workers:
                type: int
                description: Deprecated, please rename it to fabric_workers. Number of worker processes for Security Fabric daemon.
            file-mgmt:
                type: str
                description:
                    - Deprecated, please rename it to file_mgmt.
                    - Enable/disable Security Fabric daemon file management.
                    - disable - Disable daemon file management.
                    - enable - Enable daemon file management.
                choices:
                    - 'disable'
                    - 'enable'
            file-quota:
                type: int
                description: Deprecated, please rename it to file_quota. Maximum amount of memory that can be used by the daemon files
            file-quota-warning:
                type: int
                description: Deprecated, please rename it to file_quota_warning. Warn when the set percentage of quota has been used.
            fixed-key:
                type: list
                elements: str
                description: Deprecated, please rename it to fixed_key.
            forticloud-account-enforcement:
                type: str
                description:
                    - Deprecated, please rename it to forticloud_account_enforcement.
                    - Fabric FortiCloud account unification.
                    - disable - Disable FortiCloud accound ID matching for Security Fabric.
                    - enable - Enable FortiCloud account ID matching for Security Fabric.
                choices:
                    - 'disable'
                    - 'enable'
            group-name:
                type: str
                description: Deprecated, please rename it to group_name. Security Fabric group name.
            group-password:
                type: list
                elements: str
                description: Deprecated, please rename it to group_password.
            log-unification:
                type: str
                description:
                    - Deprecated, please rename it to log_unification.
                    - Enable/disable broadcast of discovery messages for log unification.
                    - disable - Disable broadcast of discovery messages for log unification.
                    - enable - Enable broadcast of discovery messages for log unification.
                choices:
                    - 'disable'
                    - 'enable'
            saml-configuration-sync:
                type: str
                description:
                    - Deprecated, please rename it to saml_configuration_sync.
                    - SAML setting configuration synchronization.
                    - local - Do not apply SAML configuration generated by root.
                    - default - SAML setting for fabric members is created by fabric root.
                choices:
                    - 'local'
                    - 'default'
            status:
                type: str
                description:
                    - Enable/disable Security Fabric.
                    - disable - Disable Security Fabric.
                    - enable - Enable Security Fabric.
                choices:
                    - 'disable'
                    - 'enable'
            trusted-list:
                type: list
                elements: dict
                description: Deprecated, please rename it to trusted_list.
                suboptions:
                    action:
                        type: str
                        description:
                            - Security fabric authorization action.
                            - accept - Accept authorization request.
                            - deny - Deny authorization request.
                        choices:
                            - 'accept'
                            - 'deny'
                    authorization-type:
                        type: str
                        description:
                            - Deprecated, please rename it to authorization_type.
                            - Authorization type.
                            - serial - Verify downstream by serial number.
                            - certificate - Verify downstream by certificate.
                        choices:
                            - 'serial'
                            - 'certificate'
                    certificate:
                        type: str
                        description: Certificate.
                    downstream-authorization:
                        type: str
                        description:
                            - Deprecated, please rename it to downstream_authorization.
                            - Trust authorizations by this node&apos;s administrator.
                            - disable - Disable downstream authorization.
                            - enable - Enable downstream authorization.
                        choices:
                            - 'disable'
                            - 'enable'
                    ha-members:
                        type: str
                        description: Deprecated, please rename it to ha_members. HA members.
                    index:
                        type: int
                        description: Index of the downstream in tree.
                    name:
                        type: str
                        description: Name.
                    serial:
                        type: str
                        description: Serial.
            upstream:
                type: str
                description: IP/FQDN of the FortiGate upstream from this FortiGate in the Security Fabric.
            upstream-port:
                type: int
                description: Deprecated, please rename it to upstream_port. The port number to use to communicate with the FortiGate upstream from this...
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
    - name: Add this device to a Security Fabric or set up a new Security Fabric on this device.
      fortinet.fortimanager.fmgr_system_csf:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_csf:
          accept_auth_by_cert: <value in [disable, enable]>
          authorization_request_type: <value in [certificate, serial]>
          certificate: <string>
          configuration_sync: <value in [default, local]>
          downstream_access: <value in [disable, enable]>
          downstream_accprofile: <string>
          fabric_connector:
            -
              accprofile: <string>
              configuration_write_access: <value in [disable, enable]>
              serial: <string>
          fabric_object_unification: <value in [local, default]>
          fabric_workers: <integer>
          file_mgmt: <value in [disable, enable]>
          file_quota: <integer>
          file_quota_warning: <integer>
          fixed_key: <list or string>
          forticloud_account_enforcement: <value in [disable, enable]>
          group_name: <string>
          group_password: <list or string>
          log_unification: <value in [disable, enable]>
          saml_configuration_sync: <value in [local, default]>
          status: <value in [disable, enable]>
          trusted_list:
            -
              action: <value in [accept, deny]>
              authorization_type: <value in [serial, certificate]>
              certificate: <string>
              downstream_authorization: <value in [disable, enable]>
              ha_members: <string>
              index: <integer>
              name: <string>
              serial: <string>
          upstream: <string>
          upstream_port: <integer>
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
        '/cli/global/system/csf'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/csf/{csf}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_csf': {
            'type': 'dict',
            'v_range': [['7.4.1', '']],
            'options': {
                'accept-auth-by-cert': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'authorization-request-type': {'v_range': [['7.4.1', '']], 'choices': ['certificate', 'serial'], 'type': 'str'},
                'certificate': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'configuration-sync': {'v_range': [['7.4.1', '']], 'choices': ['default', 'local'], 'type': 'str'},
                'downstream-access': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'downstream-accprofile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'fabric-connector': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'accprofile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'configuration-write-access': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'serial': {'v_range': [['7.4.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-object-unification': {'v_range': [['7.4.1', '']], 'choices': ['local', 'default'], 'type': 'str'},
                'fabric-workers': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'file-mgmt': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'file-quota': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'file-quota-warning': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'fixed-key': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'forticloud-account-enforcement': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'group-name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'group-password': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'log-unification': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'saml-configuration-sync': {'v_range': [['7.4.1', '']], 'choices': ['local', 'default'], 'type': 'str'},
                'status': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trusted-list': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.1', '']], 'choices': ['accept', 'deny'], 'type': 'str'},
                        'authorization-type': {'v_range': [['7.4.1', '']], 'choices': ['serial', 'certificate'], 'type': 'str'},
                        'certificate': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'downstream-authorization': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ha-members': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'index': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'serial': {'v_range': [['7.4.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'upstream': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'upstream-port': {'v_range': [['7.4.1', '']], 'type': 'int'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_csf'),
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
