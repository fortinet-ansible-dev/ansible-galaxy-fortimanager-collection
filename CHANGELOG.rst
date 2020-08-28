===================================
Fortinet.Fortimanager Release Notes
===================================

.. contents:: Topics


v1.0.5
======

Release Summary
---------------

This collection hosts modules for FortiManager v6.0.0


New Modules
-----------

- fortinet.fortimanager.fmgr_antivirus_profile - Configure AntiVirus profiles.
- fortinet.fortimanager.fmgr_antivirus_profile_obj - Configure AntiVirus profiles.
- fortinet.fortimanager.fmgr_application_list - Configure application control lists.
- fortinet.fortimanager.fmgr_application_list_obj - Configure application control lists.
- fortinet.fortimanager.fmgr_devprof_device_profile_fortianalyzer - no description
- fortinet.fortimanager.fmgr_devprof_device_profile_fortiguard - no description
- fortinet.fortimanager.fmgr_devprof_log_syslogd_filter - Filters for remote system server.
- fortinet.fortimanager.fmgr_devprof_log_syslogd_setting - Global settings for remote syslog server.
- fortinet.fortimanager.fmgr_devprof_system_centralmanagement - Configure central management.
- fortinet.fortimanager.fmgr_devprof_system_dns - Configure DNS.
- fortinet.fortimanager.fmgr_devprof_system_emailserver - Configure the email server used by the FortiGate various things. For example, for sending email messages to users to support user authen...
- fortinet.fortimanager.fmgr_devprof_system_global - Configure global attributes.
- fortinet.fortimanager.fmgr_devprof_system_ntp - Configure system NTP information.
- fortinet.fortimanager.fmgr_devprof_system_snmp_community - SNMP community configuration.
- fortinet.fortimanager.fmgr_devprof_system_snmp_community_obj - SNMP community configuration.
- fortinet.fortimanager.fmgr_devprof_system_snmp_sysinfo - SNMP system info configuration.
- fortinet.fortimanager.fmgr_devprof_system_snmp_user - SNMP user configuration.
- fortinet.fortimanager.fmgr_devprof_system_snmp_user_obj - SNMP user configuration.
- fortinet.fortimanager.fmgr_dnsfilter_profile - Configure DNS domain filter profiles.
- fortinet.fortimanager.fmgr_dnsfilter_profile_obj - Configure DNS domain filter profiles.
- fortinet.fortimanager.fmgr_dvm_cmd_add_device - Add a device to the Device Manager database.
- fortinet.fortimanager.fmgr_dvm_cmd_del_device - Delete a device.
- fortinet.fortimanager.fmgr_dvm_cmd_discover_device - Probe a remote device and retrieve its device information and system status.
- fortinet.fortimanager.fmgr_dvm_cmd_update_device - Refresh the FGFM connection and system information of a device.
- fortinet.fortimanager.fmgr_dvmdb_device - Device table, most attributes are read-only and can only be changed internally. Refer to Device Manager Command module for API to add, d...
- fortinet.fortimanager.fmgr_dvmdb_device_obj - Device table, most attributes are read-only and can only be changed internally. Refer to Device Manager Command module for API to add, d...
- fortinet.fortimanager.fmgr_dvmdb_group - Device group table.
- fortinet.fortimanager.fmgr_dvmdb_group_obj - Device group table.
- fortinet.fortimanager.fmgr_dvmdb_script - Script table.
- fortinet.fortimanager.fmgr_dvmdb_script_execute - Run script.
- fortinet.fortimanager.fmgr_dvmdb_script_obj - Script table.
- fortinet.fortimanager.fmgr_firewall_address - Configure IPv4 addresses.
- fortinet.fortimanager.fmgr_firewall_address6 - Configure IPv6 firewall addresses.
- fortinet.fortimanager.fmgr_firewall_address6_obj - Configure IPv6 firewall addresses.
- fortinet.fortimanager.fmgr_firewall_address_obj - Configure IPv4 addresses.
- fortinet.fortimanager.fmgr_firewall_addrgrp - Configure IPv4 address groups.
- fortinet.fortimanager.fmgr_firewall_addrgrp6 - Configure IPv6 address groups.
- fortinet.fortimanager.fmgr_firewall_addrgrp6_obj - Configure IPv6 address groups.
- fortinet.fortimanager.fmgr_firewall_addrgrp_obj - Configure IPv4 address groups.
- fortinet.fortimanager.fmgr_firewall_ippool - Configure IPv4 IP pools.
- fortinet.fortimanager.fmgr_firewall_ippool6 - Configure IPv6 IP pools.
- fortinet.fortimanager.fmgr_firewall_ippool6_obj - Configure IPv6 IP pools.
- fortinet.fortimanager.fmgr_firewall_ippool_obj - Configure IPv4 IP pools.
- fortinet.fortimanager.fmgr_firewall_multicastaddress - Configure multicast addresses.
- fortinet.fortimanager.fmgr_firewall_multicastaddress_obj - Configure multicast addresses.
- fortinet.fortimanager.fmgr_firewall_profilegroup - Configure profile groups.
- fortinet.fortimanager.fmgr_firewall_profilegroup_obj - Configure profile groups.
- fortinet.fortimanager.fmgr_firewall_service_category - Configure service categories.
- fortinet.fortimanager.fmgr_firewall_service_category_obj - Configure service categories.
- fortinet.fortimanager.fmgr_firewall_service_custom - Configure custom services.
- fortinet.fortimanager.fmgr_firewall_service_custom_obj - Configure custom services.
- fortinet.fortimanager.fmgr_firewall_service_group - Configure service groups.
- fortinet.fortimanager.fmgr_firewall_service_group_obj - Configure service groups.
- fortinet.fortimanager.fmgr_firewall_sslsshprofile - Configure SSL/SSH protocol options.
- fortinet.fortimanager.fmgr_firewall_sslsshprofile_obj - Configure SSL/SSH protocol options.
- fortinet.fortimanager.fmgr_firewall_vip - Configure virtual IP for IPv4.
- fortinet.fortimanager.fmgr_firewall_vip_obj - Configure virtual IP for IPv4.
- fortinet.fortimanager.fmgr_ips_sensor - Configure IPS sensor.
- fortinet.fortimanager.fmgr_ips_sensor_obj - Configure IPS sensor.
- fortinet.fortimanager.fmgr_pkg_firewall_policy - Configure IPv4 policies.
- fortinet.fortimanager.fmgr_pkg_firewall_policy_obj - Configure IPv4 policies.
- fortinet.fortimanager.fmgr_pm_devprof_adom_obj - no description
- fortinet.fortimanager.fmgr_pm_devprof_obj - no description
- fortinet.fortimanager.fmgr_pm_pkg_adom_obj - no description
- fortinet.fortimanager.fmgr_pm_pkg_obj - no description
- fortinet.fortimanager.fmgr_securityconsole_install_device - no description
- fortinet.fortimanager.fmgr_securityconsole_install_package - Copy and install a policy package to devices.
- fortinet.fortimanager.fmgr_spamfilter_profile - Configure AntiSpam profiles.
- fortinet.fortimanager.fmgr_spamfilter_profile_obj - Configure AntiSpam profiles.
- fortinet.fortimanager.fmgr_system_global - Global range attributes.
- fortinet.fortimanager.fmgr_system_ha - HA configuration.
- fortinet.fortimanager.fmgr_system_ha_peer - Peer.
- fortinet.fortimanager.fmgr_system_interface - Interface configuration.
- fortinet.fortimanager.fmgr_system_interface_obj - Interface configuration.
- fortinet.fortimanager.fmgr_task_task - Read-only table containing the 10000 most recent tasks of the system. This table can be used for tracking non-blocking tasks initiated b...
- fortinet.fortimanager.fmgr_task_task_obj - Read-only table containing the 10000 most recent tasks of the system. This table can be used for tracking non-blocking tasks initiated b...
- fortinet.fortimanager.fmgr_voip_profile - Configure VoIP profiles.
- fortinet.fortimanager.fmgr_voip_profile_obj - Configure VoIP profiles.
- fortinet.fortimanager.fmgr_waf_profile - Web application firewall configuration.
- fortinet.fortimanager.fmgr_waf_profile_obj - Web application firewall configuration.
- fortinet.fortimanager.fmgr_wanopt_profile - Configure WAN optimization profiles.
- fortinet.fortimanager.fmgr_wanopt_profile_obj - Configure WAN optimization profiles.
- fortinet.fortimanager.fmgr_webfilter_profile - Configure Web filter profiles.
- fortinet.fortimanager.fmgr_webfilter_profile_obj - Configure Web filter profiles.
- fortinet.fortimanager.fmgr_webproxy_profile - Configure web proxy profiles.
- fortinet.fortimanager.fmgr_webproxy_profile_obj - Configure web proxy profiles.
