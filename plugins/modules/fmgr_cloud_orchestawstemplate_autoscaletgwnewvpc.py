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
module: fmgr_cloud_orchestawstemplate_autoscaletgwnewvpc
short_description: no description
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
    cloud_orchestawstemplate_autoscaletgwnewvpc:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            availability-zones:
                type: str
                description: Deprecated, please rename it to availability_zones.
            bgp-asn:
                type: int
                description: Deprecated, please rename it to bgp_asn.
            custom-asset-container:
                type: str
                description: Deprecated, please rename it to custom_asset_container.
            custom-asset-directory:
                type: str
                description: Deprecated, please rename it to custom_asset_directory.
            custom-identifier:
                type: str
                description: Deprecated, please rename it to custom_identifier.
            faz-autoscale-admin-password:
                type: raw
                description: (list) Deprecated, please rename it to faz_autoscale_admin_password.
            faz-autoscale-admin-username:
                type: str
                description: Deprecated, please rename it to faz_autoscale_admin_username.
            faz-custom-private-ipaddress:
                type: str
                description: Deprecated, please rename it to faz_custom_private_ipaddress.
            faz-instance-type:
                type: str
                description: Deprecated, please rename it to faz_instance_type.
                choices:
                    - 'h1.2xlarge'
                    - 'h1.4xlarge'
                    - 'h1.8xlarge'
                    - 'm5.large'
                    - 'm5.xlarge'
                    - 'm5.2xlarge'
                    - 'm5.4xlarge'
                    - 'm5.12xlarge'
                    - 't2.medium'
                    - 't2.large'
                    - 't2.xlarge'
            faz-integration-options:
                type: str
                description: Deprecated, please rename it to faz_integration_options.
                choices:
                    - 'no'
                    - 'yes'
            faz-version:
                type: str
                description: Deprecated, please rename it to faz_version.
            fgt-admin-cidr:
                type: str
                description: Deprecated, please rename it to fgt_admin_cidr.
            fgt-admin-port:
                type: int
                description: Deprecated, please rename it to fgt_admin_port.
            fgt-instance-type:
                type: str
                description: Deprecated, please rename it to fgt_instance_type.
                choices:
                    - 't2.small'
                    - 'c5.large'
                    - 'c5.xlarge'
                    - 'c5.2xlarge'
                    - 'c5.4xlarge'
                    - 'c5.9xlarge'
            fgt-psk-secret:
                type: str
                description: Deprecated, please rename it to fgt_psk_secret.
            fgtasg-cool-down:
                type: int
                description: Deprecated, please rename it to fgtasg_cool_down.
            fgtasg-desired-capacity-byol:
                type: int
                description: Deprecated, please rename it to fgtasg_desired_capacity_byol.
            fgtasg-desired-capacity-payg:
                type: int
                description: Deprecated, please rename it to fgtasg_desired_capacity_payg.
            fgtasg-health-check-grace-period:
                type: int
                description: Deprecated, please rename it to fgtasg_health_check_grace_period.
            fgtasg-max-size-byol:
                type: int
                description: Deprecated, please rename it to fgtasg_max_size_byol.
            fgtasg-max-size-payg:
                type: int
                description: Deprecated, please rename it to fgtasg_max_size_payg.
            fgtasg-min-size-byol:
                type: int
                description: Deprecated, please rename it to fgtasg_min_size_byol.
            fgtasg-min-size-payg:
                type: int
                description: Deprecated, please rename it to fgtasg_min_size_payg.
            fgtasg-scale-in-threshold:
                type: int
                description: Deprecated, please rename it to fgtasg_scale_in_threshold.
            fgtasg-scale-out-threshold:
                type: int
                description: Deprecated, please rename it to fgtasg_scale_out_threshold.
            fos-version:
                type: str
                description: Deprecated, please rename it to fos_version.
            get-license-grace-period:
                type: int
                description: Deprecated, please rename it to get_license_grace_period.
            heartbeat-delay-allowance:
                type: int
                description: Deprecated, please rename it to heartbeat_delay_allowance.
            heartbeat-interval:
                type: int
                description: Deprecated, please rename it to heartbeat_interval.
            heartbeat-loss-count:
                type: int
                description: Deprecated, please rename it to heartbeat_loss_count.
            key-pair-name:
                type: str
                description: Deprecated, please rename it to key_pair_name.
            lifecycle-hook-timeout:
                type: int
                description: Deprecated, please rename it to lifecycle_hook_timeout.
            name:
                type: str
                description: No description.
                required: true
            notification-email:
                type: str
                description: Deprecated, please rename it to notification_email.
            primary-election-timeout:
                type: int
                description: Deprecated, please rename it to primary_election_timeout.
            public-subnet1-cidr:
                type: str
                description: Deprecated, please rename it to public_subnet1_cidr.
            public-subnet2-cidr:
                type: str
                description: Deprecated, please rename it to public_subnet2_cidr.
            resource-tag-prefix:
                type: str
                description: Deprecated, please rename it to resource_tag_prefix.
            s3-bucket-name:
                type: str
                description: Deprecated, please rename it to s3_bucket_name.
            s3-key-prefix:
                type: str
                description: Deprecated, please rename it to s3_key_prefix.
            sync-recovery-count:
                type: int
                description: Deprecated, please rename it to sync_recovery_count.
            terminate-unhealthy-vm:
                type: str
                description: Deprecated, please rename it to terminate_unhealthy_vm.
                choices:
                    - 'no'
                    - 'yes'
            transit-gateway-id:
                type: str
                description: Deprecated, please rename it to transit_gateway_id.
            transit-gateway-support-options:
                type: str
                description: Deprecated, please rename it to transit_gateway_support_options.
                choices:
                    - 'create one'
                    - 'use an existing one'
            use-custom-asset-location:
                type: str
                description: Deprecated, please rename it to use_custom_asset_location.
                choices:
                    - 'no'
                    - 'yes'
            vpc-cidr:
                type: str
                description: Deprecated, please rename it to vpc_cidr.
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
    - name: No description
      fortinet.fortimanager.fmgr_cloud_orchestawstemplate_autoscaletgwnewvpc:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        cloud_orchestawstemplate_autoscaletgwnewvpc:
          availability_zones: <string>
          bgp_asn: <integer>
          custom_asset_container: <string>
          custom_asset_directory: <string>
          custom_identifier: <string>
          faz_autoscale_admin_password: <list or string>
          faz_autoscale_admin_username: <string>
          faz_custom_private_ipaddress: <string>
          faz_instance_type: <value in [h1.2xlarge, h1.4xlarge, h1.8xlarge, ...]>
          faz_integration_options: <value in [no, yes]>
          faz_version: <string>
          fgt_admin_cidr: <string>
          fgt_admin_port: <integer>
          fgt_instance_type: <value in [t2.small, c5.large, c5.xlarge, ...]>
          fgt_psk_secret: <string>
          fgtasg_cool_down: <integer>
          fgtasg_desired_capacity_byol: <integer>
          fgtasg_desired_capacity_payg: <integer>
          fgtasg_health_check_grace_period: <integer>
          fgtasg_max_size_byol: <integer>
          fgtasg_max_size_payg: <integer>
          fgtasg_min_size_byol: <integer>
          fgtasg_min_size_payg: <integer>
          fgtasg_scale_in_threshold: <integer>
          fgtasg_scale_out_threshold: <integer>
          fos_version: <string>
          get_license_grace_period: <integer>
          heartbeat_delay_allowance: <integer>
          heartbeat_interval: <integer>
          heartbeat_loss_count: <integer>
          key_pair_name: <string>
          lifecycle_hook_timeout: <integer>
          name: <string>
          notification_email: <string>
          primary_election_timeout: <integer>
          public_subnet1_cidr: <string>
          public_subnet2_cidr: <string>
          resource_tag_prefix: <string>
          s3_bucket_name: <string>
          s3_key_prefix: <string>
          sync_recovery_count: <integer>
          terminate_unhealthy_vm: <value in [no, yes]>
          transit_gateway_id: <string>
          transit_gateway_support_options: <value in [create one, use an existing one]>
          use_custom_asset_location: <value in [no, yes]>
          vpc_cidr: <string>
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
        '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc',
        '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc/{autoscale-tgw-new-vpc}',
        '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc/{autoscale-tgw-new-vpc}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'cloud_orchestawstemplate_autoscaletgwnewvpc': {
            'type': 'dict',
            'v_range': [['7.4.0', '']],
            'options': {
                'availability-zones': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'bgp-asn': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'custom-asset-container': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'custom-asset-directory': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'custom-identifier': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'faz-autoscale-admin-password': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'raw'},
                'faz-autoscale-admin-username': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'faz-custom-private-ipaddress': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'faz-instance-type': {
                    'v_range': [['7.4.0', '']],
                    'choices': [
                        'h1.2xlarge', 'h1.4xlarge', 'h1.8xlarge', 'm5.large', 'm5.xlarge', 'm5.2xlarge', 'm5.4xlarge', 'm5.12xlarge', 't2.medium',
                        't2.large', 't2.xlarge'
                    ],
                    'type': 'str'
                },
                'faz-integration-options': {'v_range': [['7.4.0', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'faz-version': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'fgt-admin-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'fgt-admin-port': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgt-instance-type': {
                    'v_range': [['7.4.0', '']],
                    'choices': ['t2.small', 'c5.large', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge', 'c5.9xlarge'],
                    'type': 'str'
                },
                'fgt-psk-secret': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'str'},
                'fgtasg-cool-down': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-desired-capacity-byol': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-desired-capacity-payg': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-health-check-grace-period': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-max-size-byol': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-max-size-payg': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-min-size-byol': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-min-size-payg': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-scale-in-threshold': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-scale-out-threshold': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fos-version': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'get-license-grace-period': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'heartbeat-delay-allowance': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'heartbeat-interval': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'heartbeat-loss-count': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'key-pair-name': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'str'},
                'lifecycle-hook-timeout': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.0', '']], 'required': True, 'type': 'str'},
                'notification-email': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'primary-election-timeout': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'public-subnet1-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'public-subnet2-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'resource-tag-prefix': {'v_range': [['7.4.0', '']], 'type': 'str'},
                's3-bucket-name': {'v_range': [['7.4.0', '']], 'type': 'str'},
                's3-key-prefix': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'str'},
                'sync-recovery-count': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'terminate-unhealthy-vm': {'v_range': [['7.4.0', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'transit-gateway-id': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'transit-gateway-support-options': {'v_range': [['7.4.0', '']], 'choices': ['create one', 'use an existing one'], 'type': 'str'},
                'use-custom-asset-location': {'v_range': [['7.4.0', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'vpc-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cloud_orchestawstemplate_autoscaletgwnewvpc'),
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
