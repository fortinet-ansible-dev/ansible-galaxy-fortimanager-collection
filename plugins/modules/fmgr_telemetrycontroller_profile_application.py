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
module: fmgr_telemetrycontroller_profile_application
short_description: Configure applications.
version_added: "2.10.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    telemetrycontroller_profile_application:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app_name:
                aliases: ['app-name']
                type: list
                elements: str
                description: Application name.
            app_throughput:
                aliases: ['app-throughput']
                type: int
                description: Application throughput in megabytes
            atdt_threshold:
                aliases: ['atdt-threshold']
                type: int
                description: Threshold of application total downloading time in milliseconds
            dns_time_threshold:
                aliases: ['dns-time-threshold']
                type: int
                description: Threshold of DNS resolution time in milliseconds
            experience_score_threshold:
                aliases: ['experience-score-threshold']
                type: int
                description: Threshold of experience score
            failure_rate_threshold:
                aliases: ['failure-rate-threshold']
                type: int
                description: Threshold of failure rate
            id:
                type: int
                description: ID.
                required: true
            interval:
                type: int
                description: Time in milliseconds to check the application
            jitter_threshold:
                aliases: ['jitter-threshold']
                type: int
                description: Threshold of jitter in milliseconds
            latency_threshold:
                aliases: ['latency-threshold']
                type: int
                description: Threshold of latency in milliseconds
            monitor:
                type: str
                description: Enable/disable monitoring of the application.
                choices: ['disable', 'enable']
            packet_loss_threshold:
                aliases: ['packet-loss-threshold']
                type: int
                description: Threshold of packet loss
            sla:
                type: dict
                description: Sla.
                suboptions:
                    app_throughput_threshold:
                        aliases: ['app-throughput-threshold']
                        type: int
                        description: Threshold of application throughput in megabytes
                    atdt_threshold:
                        aliases: ['atdt-threshold']
                        type: int
                        description: Threshold of application total downloading time in milliseconds
                    dns_time_threshold:
                        aliases: ['dns-time-threshold']
                        type: int
                        description: Threshold of 95th percentile of DNS resolution time in milliseconds
                    experience_score_threshold:
                        aliases: ['experience-score-threshold']
                        type: int
                        description: Threshold of experience score
                    failure_rate_threshold:
                        aliases: ['failure-rate-threshold']
                        type: int
                        description: Threshold of failure rate
                    jitter_threshold:
                        aliases: ['jitter-threshold']
                        type: int
                        description: Threshold of jitter in milliseconds
                    latency_threshold:
                        aliases: ['latency-threshold']
                        type: int
                        description: Threshold of latency in milliseconds
                    packet_loss_threshold:
                        aliases: ['packet-loss-threshold']
                        type: int
                        description: Threshold of packet loss
                    sla_factor:
                        aliases: ['sla-factor']
                        type: list
                        elements: str
                        description: Criteria on which metric to SLA threshold list.
                        choices: ['latency', 'jitter', 'packet-loss', 'experience-score',
                                  'failure-rate', 'ttfb', 'atdt', 'tcp-rtt', 'dns-time',
                                  'tls-time', 'app-throughput']
                    tcp_rtt_threshold:
                        aliases: ['tcp-rtt-threshold']
                        type: int
                        description: Threshold of TCP round-trip time in milliseconds
                    tls_time_threshold:
                        aliases: ['tls-time-threshold']
                        type: int
                        description: Threshold of 95th percentile of TLS handshake time in milliseconds
                    ttfb_threshold:
                        aliases: ['ttfb-threshold']
                        type: int
                        description: Threshold of time to first byte in milliseconds
            tcp_rtt_threshold:
                aliases: ['tcp-rtt-threshold']
                type: int
                description: Threshold of TCP round-trip time in milliseconds
            tls_time_threshold:
                aliases: ['tls-time-threshold']
                type: int
                description: Threshold of TLS handshake time in milliseconds
            ttfb_threshold:
                aliases: ['ttfb-threshold']
                type: int
                description: Threshold of time to first byte in milliseconds
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure applications.
      fortinet.fortimanager.fmgr_telemetrycontroller_profile_application:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        telemetrycontroller_profile_application:
          id: 0 # Required variable, integer
          # app_name: <list or string>
          # app_throughput: <integer>
          # atdt_threshold: <integer>
          # dns_time_threshold: <integer>
          # experience_score_threshold: <integer>
          # failure_rate_threshold: <integer>
          # interval: <integer>
          # jitter_threshold: <integer>
          # latency_threshold: <integer>
          # monitor: <value in [disable, enable]>
          # packet_loss_threshold: <integer>
          # sla:
          #   app_throughput_threshold: <integer>
          #   atdt_threshold: <integer>
          #   dns_time_threshold: <integer>
          #   experience_score_threshold: <integer>
          #   failure_rate_threshold: <integer>
          #   jitter_threshold: <integer>
          #   latency_threshold: <integer>
          #   packet_loss_threshold: <integer>
          #   sla_factor: ["latency", "jitter", "packet-loss", "experience-score", "failure-rate",
          #                "ttfb", "atdt", "tcp-rtt", "dns-time", "tls-time", "app-throughput"]
          #   tcp_rtt_threshold: <integer>
          #   tls_time_threshold: <integer>
          #   ttfb_threshold: <integer>
          # tcp_rtt_threshold: <integer>
          # tls_time_threshold: <integer>
          # ttfb_threshold: <integer>
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
        '/pm/config/adom/{adom}/obj/telemetry-controller/profile/{profile}/application',
        '/pm/config/global/obj/telemetry-controller/profile/{profile}/application'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'telemetrycontroller_profile_application': {
            'type': 'dict', 'v_range': [['7.6.3', '']],
            'options': {
                'app-name': {'v_range': [['7.6.3', '']], 'type': 'list', 'elements': 'str'},
                'app-throughput': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'atdt-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'dns-time-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'experience-score-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'failure-rate-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'id': {'v_range': [['7.6.3', '']], 'required': True, 'type': 'int'},
                'interval': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'jitter-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'latency-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'monitor': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'packet-loss-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'sla': {
                    'v_range': [['7.6.3', '']],
                    'type': 'dict',
                    'options': {
                        'app-throughput-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'atdt-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'dns-time-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'experience-score-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'failure-rate-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'jitter-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'latency-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'packet-loss-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'sla-factor': {
                            'v_range': [['7.6.3', '']],
                            'type': 'list',
                            'choices': [
                                'latency', 'jitter', 'packet-loss', 'experience-score', 'failure-rate', 'ttfb', 'atdt', 'tcp-rtt', 'dns-time',
                                'tls-time', 'app-throughput'
                            ],
                            'elements': 'str'
                        },
                        'tcp-rtt-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'tls-time-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'ttfb-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'}
                    }
                },
                'tcp-rtt-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'tls-time-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'},
                'ttfb-threshold': {'v_range': [['7.6.3', '7.6.3']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'telemetrycontroller_profile_application'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
