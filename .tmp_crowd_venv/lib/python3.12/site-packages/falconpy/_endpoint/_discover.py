"""Internal API endpoint constant library.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""

_discover_endpoints = [
  [
    "combined_applications",
    "GET",
    "/discover/combined/applications/v1",
    "Search for applications in your environment by providing an FQL filter and paging details. Returns "
    "details on applications which match the filter criteria.",
    "discover",
    [
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an after token. On subsequent requests, provide the after token from the "
        "previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "description": "The number of application ids to return in this response (Min: 1, Max: 1000, Default: "
        "100). Use with the after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort applications by their properties. A single sort field is allowed.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Search for applications in your environment by providing an FQL "
        "filter.\n\t\t\t\tAvailable filter fields that support exact match: name, version, vendor, name_vendor, "
        "name_vendor_version, first_seen_timestamp, installation_timestamp, architectures, installation_paths, "
        "versioning_scheme, groups, is_normalized, last_used_user_sid, last_used_user_name, last_used_file_name, "
        "last_used_file_hash, last_used_timestamp, last_updated_timestamp, is_suspicious, host.id, host.platform_name, "
        "host.hostname, cid, host.os_version, host.machine_domain, host.ou, host.site_name, host.country, "
        "host.current_mac_address, host.current_network_prefix, host.tags, host.groups, host.product_type_desc, "
        "host.kernel_version, host.system_manufacturer, host.internet_exposure, host.agent_version, host.external_ip, "
        "host.aid\n\t\t\t\tAvailable filter fields that supports wildcard (*): name, version, vendor, name_vendor, "
        "name_vendor_version, architectures, installation_paths, groups, last_used_user_sid, last_used_user_name, "
        "last_used_file_name, last_used_file_hash, host.platform_name, host.hostname, cid, host.os_version, "
        "host.machine_domain, host.ou, host.site_name, host.country, host.current_mac_address, "
        "host.current_network_prefix, host.tags, host.groups, host.product_type_desc, host.kernel_version, "
        "host.system_manufacturer, host.internet_exposure, host.agent_version, host.external_ip, "
        "host.aid\n\t\t\t\tAvailable filter fields that supports range comparisons (>, <, >=, <=): "
        "first_seen_timestamp, installation_timestamp, last_used_timestamp, last_updated_timestamp\n\t\t\t\tAll filter "
        "fields and operations supports negation (!).",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Select various details blocks to be returned for each application entity. Supported va "
        "lues:\n\n<ul><li>browser_extension</li><li>host_info</li><li>install_usage</li><li>package</li><li>ide_extensi "
        "on</li></ul>",
        "name": "facet",
        "in": "query"
      }
    ]
  ],
  [
    "combined_hosts",
    "GET",
    "/discover/combined/hosts/v1",
    "Search for assets in your environment by providing an FQL (Falcon Query Language) filter and paging "
    "details. Returns details on assets which match the filter criteria.",
    "discover",
    [
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an after token. On subsequent requests, provide the after token from the "
        "previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "description": "The number of asset IDs to return in this response (min: 1, max: 1000, default: 100). "
        "Use with the after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort assets by their properties. A single sort field is allowed. Common sort options "
        "include:\n\n<ul><li>hostname|asc</li><li>product_type_desc|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter assets using an FQL query. Common filter options include:<ul><li>entity_type:'m "
        "anaged'</li><li>product_type_desc:'Workstation'</li><li>platform_name:'Windows'</li><li>last_seen_timestamp:>' "
        "now-7d'</li></ul>\n\t\t\tAvailable filter fields that support exact match: id, aid, entity_type, country, "
        "city, platform_name, os_version, kernel_version, product_type_desc, tags, groups, agent_version, "
        "system_product_name, system_manufacturer, system_serial_number, bios_manufacturer, bios_version, ou, "
        "machine_domain, site_name, external_ip, hostname, local_ips_count, network_interfaces.local_ip, "
        "network_interfaces.mac_address, network_interfaces.interface_alias, network_interfaces.interface_description, "
        "network_interfaces.network_prefix, last_discoverer_aid, discoverer_count, discoverer_aids, discoverer_tags, "
        "discoverer_platform_names, discoverer_product_type_descs, confidence, internet_exposure,  os_is_eol, "
        "data_providers, data_providers_count, mac_addresses, local_ip_addresses, reduced_functionality_mode, "
        "number_of_disk_drives, processor_package_count, physical_core_count, logical_core_count, total_disk_space, "
        "disk_sizes.disk_name, disk_sizes.disk_space, cpu_processor_name, total_memory, encryption_status, "
        "encrypted_drives, encrypted_drives_count, unencrypted_drives, unencrypted_drives_count, "
        "os_security.secure_boot_requested_status, os_security.device_guard_status, os_security.device_guard_status, "
        "os_security.device_guard_status, os_security.system_guard_status, os_security.credential_guard_status, "
        "os_security.iommu_protection_status, os_security.secure_boot_enabled_status, "
        "os_security.uefi_memory_protection_status, os_security.virtualization_based_security_status, "
        "os_security.kernel_dma_protection_status, total_bios_files, bios_hashes_data.sha256_hash, "
        "bios_hashes_data.measurement_type, bios_id, average_processor_usage, average_memory_usage, "
        "average_memory_usage_pct, max_processor_usage, max_memory_usage, max_memory_usage_pct, used_disk_space, "
        "used_disk_space_pct, available_disk_space, available_disk_space_pct, mount_storage_info.mount_path, "
        "mount_storage_info.used_space, mount_storage_info.available_space, form_factor, servicenow_id, owned_by, "
        "managed_by, assigned_to, department, fqdn, used_for, object_guid, object_sid, ad_user_account_control, "
        "account_enabled, creation_timestamp, email, os_service_pack, location, state, cpu_manufacturer, "
        "discovering_by, scan_details.scan_id, scan_details.schedule_id\n\t\t\tAvailable filter fields that supports "
        "wildcard (*): id, aid, entity_type, country, city, platform_name, os_version, kernel_version, "
        "product_type_desc, tags, groups, agent_version, system_product_name, system_manufacturer, "
        "system_serial_number, bios_manufacturer, bios_version, ou, machine_domain, site_name, external_ip, hostname, "
        "network_interfaces.local_ip, network_interfaces.mac_address, network_interfaces.interface_alias, "
        "network_interfaces.interface_description, network_interfaces.network_prefix, last_discoverer_aid, "
        "discoverer_aids, discoverer_tags, discoverer_platform_names, discoverer_product_type_descs, confidence, "
        "internet_exposure,  os_is_eol, data_providers, mac_addresses, local_ip_addresses, reduced_functionality_mode, "
        "disk_sizes.disk_name, cpu_processor_name, encryption_status, encrypted_drives, unencrypted_drives, "
        "os_security.secure_boot_requested_status, os_security.device_guard_status, os_security.device_guard_status, "
        "os_security.device_guard_status, os_security.system_guard_status, os_security.credential_guard_status, "
        "os_security.iommu_protection_status, os_security.secure_boot_enabled_status, "
        "os_security.uefi_memory_protection_status, os_security.virtualization_based_security_status, "
        "os_security.kernel_dma_protection_status, bios_hashes_data.sha256_hash, bios_hashes_data.measurement_type, "
        "bios_id, mount_storage_info.mount_path, form_factor, servicenow_id, owned_by, managed_by, assigned_to, "
        "department, fqdn, used_for, object_guid, object_sid, account_enabled, email, os_service_pack, location, state, "
        " cpu_manufacturer, discovering_by, scan_details.scan_id, scan_details.schedule_id\n\t\t\tAvailable filter "
        "fields that supports range comparisons (>, <, >=, <=): first_seen_timestamp, last_seen_timestamp, "
        "local_ips_count, discoverer_count, confidence, number_of_disk_drives, processor_package_count, "
        "physical_core_count, data_providers_count, logical_core_count, total_disk_space, disk_sizes.disk_space, "
        "total_memory, encrypted_drives_count, unencrypted_drives_count, total_bios_files, average_processor_usage, "
        "average_memory_usage, average_memory_usage_pct, max_processor_usage, max_memory_usage, max_memory_usage_pct, "
        "used_disk_space, used_disk_space_pct, available_disk_space, available_disk_space_pct, "
        "mount_storage_info.used_space, mount_storage_info.available_space, ad_user_account_control, "
        "creation_timestamp, scan_details.scan_date, vulnerability_assessment_date\n\t\t\tAll filter fields and "
        "operations supports negation (!).",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Select various details blocks to be returned for each host entity. Supported "
        "values:\n\n<ul><li>system_insights</li><li>third_party</li><li>risk_factors</li></ul>",
        "name": "facet",
        "in": "query"
      }
    ]
  ],
  [
    "get_accounts",
    "GET",
    "/discover/entities/accounts/v1",
    "Get details on accounts by providing one or more IDs.",
    "discover",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more account IDs (max: 100). Find account IDs with GET /discover/queries/accounts/v1",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "get_applications",
    "GET",
    "/discover/entities/applications/v1",
    "Get details on applications by providing one or more IDs.",
    "discover",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of applications to retrieve. (Min: 1, Max: 100)",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "get_hosts",
    "GET",
    "/discover/entities/hosts/v1",
    "Get details on assets by providing one or more IDs.",
    "discover",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more asset IDs (max: 100). Find asset IDs with GET /discover/queries/hosts/v1",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "get_iot_hosts",
    "GET",
    "/discover/entities/iot-hosts/v1",
    "Get details on IoT assets by providing one or more IDs.",
    "discover",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more asset IDs (max: 100). Find asset IDs with GET /discover/queries/iot-hosts/v1",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "get_logins",
    "GET",
    "/discover/entities/logins/v1",
    "Get details on logins by providing one or more IDs.",
    "discover",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more login IDs (max: 100). Find login IDs with GET /discover/queries/logins/v1",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "query_accounts",
    "GET",
    "/discover/queries/accounts/v1",
    "Search for accounts in your environment by providing an FQL (Falcon Query Language) filter and paging "
    "details. Returns a set of account IDs which match the filter criteria.",
    "discover",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "An offset used with the limit parameter to manage pagination of results. On your first "
        " request, don’t provide an offset. On subsequent requests, add previous offset with the previous limit to "
        "continue from that place in the results.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 100,
        "minimum": 1,
        "type": "integer",
        "description": "The number of account IDs to return in this response (min: 1, max: 100, default: 100). "
        "Use with the offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort accounts by their properties. A single sort field is allowed. Common sort options "
        "include:\n\n<ul><li>username|asc</li><li>last_failed_login_timestamp|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter accounts using an FQL query. Common filter options include:<ul><li>account_type "
        ":'Local'</li><li>admin_privileges:'Yes'</li><li>first_seen_timestamp:<'now-"
        "7d'</li><li>last_successful_login_type:'Terminal server'</li></ul>\n\t\t\tAvailable filter fields that support "
        " exact match: id, cid, user_sid, account_name, username, account_type, admin_privileges, first_seen_timestamp, "
        " last_successful_login_type, last_successful_login_timestamp, last_successful_login_hostname, "
        "last_successful_login_remote_ip, last_successful_login_host_country, last_successful_login_host_city, "
        "login_domain, last_failed_login_type, last_failed_login_timestamp, last_failed_login_hostname, "
        "password_last_set_timestamp, local_admin_privileges\n\t\t\tAvailable filter fields that supports wildcard (*): "
        " id, cid, user_sid, account_name, username, account_type, admin_privileges, last_successful_login_type, "
        "last_successful_login_hostname, last_successful_login_remote_ip, last_successful_login_host_country, "
        "last_successful_login_host_city, login_domain, last_failed_login_type, last_failed_login_hostname, "
        "local_admin_privileges\n\t\t\tAvailable filter fields that supports range comparisons (>, <, >=, <=): "
        "first_seen_timestamp, last_successful_login_timestamp,last_failed_login_timestamp, "
        "password_last_set_timestamp\n\t\t\tAll filter fields and operations supports negation (!).",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "query_applications",
    "GET",
    "/discover/queries/applications/v1",
    "Search for applications in your environment by providing an FQL filter and paging details. returns a set "
    "of application IDs which match the filter criteria.",
    "discover",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "An offset used with the limit parameter to manage pagination of results. On your first "
        " request, don’t provide an offset. On subsequent requests, add previous offset with the previous limit to "
        "continue from that place in the results.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 100,
        "minimum": 1,
        "type": "integer",
        "description": "The number of application ids to return in this response (Min: 1, Max: 100, Default: 100).",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort applications by their properties. A single sort field is allowed.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Search for applications in your environment by providing an FQL "
        "filter.\n\t\t\t\tAvailable filter fields that support exact match: name, version, vendor, name_vendor, "
        "name_vendor_version, first_seen_timestamp, installation_timestamp, architectures, installation_paths, "
        "versioning_scheme, groups, is_normalized, last_used_user_sid, last_used_user_name, last_used_file_name, "
        "last_used_file_hash, last_used_timestamp, last_updated_timestamp, is_suspicious, host.id, host.platform_name, "
        "host.hostname, cid, host.os_version, host.machine_domain, host.ou, host.site_name, host.country, "
        "host.current_mac_address, host.current_network_prefix, host.tags, host.groups, host.product_type_desc, "
        "host.kernel_version, host.system_manufacturer, host.internet_exposure, host.agent_version, host.external_ip, "
        "host.aid\n\t\t\t\tAvailable filter fields that supports wildcard (*): name, version, vendor, name_vendor, "
        "name_vendor_version, architectures, installation_paths, groups, last_used_user_sid, last_used_user_name, "
        "last_used_file_name, last_used_file_hash, host.platform_name, host.hostname, cid, host.os_version, "
        "host.machine_domain, host.ou, host.site_name, host.country, host.current_mac_address, "
        "host.current_network_prefix, host.tags, host.groups, host.product_type_desc, host.kernel_version, "
        "host.system_manufacturer, host.internet_exposure, host.agent_version, host.external_ip, "
        "host.aid\n\t\t\t\tAvailable filter fields that supports range comparisons (>, <, >=, <=): "
        "first_seen_timestamp, installation_timestamp, last_used_timestamp, last_updated_timestamp\n\t\t\t\tAll filter "
        "fields and operations supports negation (!).",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "query_hosts",
    "GET",
    "/discover/queries/hosts/v1",
    "Search for assets in your environment by providing an FQL (Falcon Query Language) filter and paging "
    "details. Returns a set of asset IDs which match the filter criteria.",
    "discover",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "An offset used with the limit parameter to manage pagination of results. On your first "
        " request, don’t provide an offset. On subsequent requests, add previous offset with the previous limit to "
        "continue from that place in the results.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 100,
        "minimum": 1,
        "type": "integer",
        "description": "The number of asset IDs to return in this response (min: 1, max: 100, default: 100). "
        "Use with the offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort assets by their properties. A single sort field is allowed. Common sort options "
        "include:\n\n<ul><li>hostname|asc</li><li>product_type_desc|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter assets using an FQL query. Common filter options include:<ul><li>entity_type:'m "
        "anaged'</li><li>product_type_desc:'Workstation'</li><li>platform_name:'Windows'</li><li>last_seen_timestamp:>' "
        "now-7d'</li></ul>\n\t\t\tAvailable filter fields that support exact match: id, aid, entity_type, country, "
        "city, platform_name, os_version, kernel_version, product_type_desc, tags, groups, agent_version, "
        "system_product_name, system_manufacturer, system_serial_number, bios_manufacturer, bios_version, ou, "
        "machine_domain, site_name, external_ip, hostname, local_ips_count, network_interfaces.local_ip, "
        "network_interfaces.mac_address, network_interfaces.interface_alias, network_interfaces.interface_description, "
        "network_interfaces.network_prefix, last_discoverer_aid, discoverer_count, discoverer_aids, discoverer_tags, "
        "discoverer_platform_names, discoverer_product_type_descs, confidence, internet_exposure,  os_is_eol, "
        "data_providers, data_providers_count, mac_addresses, local_ip_addresses, reduced_functionality_mode, "
        "number_of_disk_drives, processor_package_count, physical_core_count, logical_core_count, total_disk_space, "
        "disk_sizes.disk_name, disk_sizes.disk_space, cpu_processor_name, total_memory, encryption_status, "
        "encrypted_drives, encrypted_drives_count, unencrypted_drives, unencrypted_drives_count, "
        "os_security.secure_boot_requested_status, os_security.device_guard_status, os_security.device_guard_status, "
        "os_security.device_guard_status, os_security.system_guard_status, os_security.credential_guard_status, "
        "os_security.iommu_protection_status, os_security.secure_boot_enabled_status, "
        "os_security.uefi_memory_protection_status, os_security.virtualization_based_security_status, "
        "os_security.kernel_dma_protection_status, total_bios_files, bios_hashes_data.sha256_hash, "
        "bios_hashes_data.measurement_type, bios_id, average_processor_usage, average_memory_usage, "
        "average_memory_usage_pct, max_processor_usage, max_memory_usage, max_memory_usage_pct, used_disk_space, "
        "used_disk_space_pct, available_disk_space, available_disk_space_pct, mount_storage_info.mount_path, "
        "mount_storage_info.used_space, mount_storage_info.available_space, form_factor, servicenow_id, owned_by, "
        "managed_by, assigned_to, department, fqdn, used_for, object_guid, object_sid, ad_user_account_control, "
        "account_enabled, creation_timestamp, email, os_service_pack, location, state, cpu_manufacturer, "
        "discovering_by, scan_details.scan_id, scan_details.schedule_id\n\t\t\tAvailable filter fields that supports "
        "wildcard (*): id, aid, entity_type, country, city, platform_name, os_version, kernel_version, "
        "product_type_desc, tags, groups, agent_version, system_product_name, system_manufacturer, "
        "system_serial_number, bios_manufacturer, bios_version, ou, machine_domain, site_name, external_ip, hostname, "
        "network_interfaces.local_ip, network_interfaces.mac_address, network_interfaces.interface_alias, "
        "network_interfaces.interface_description, network_interfaces.network_prefix, last_discoverer_aid, "
        "discoverer_aids, discoverer_tags, discoverer_platform_names, discoverer_product_type_descs, confidence, "
        "internet_exposure,  os_is_eol, data_providers, mac_addresses, local_ip_addresses, reduced_functionality_mode, "
        "disk_sizes.disk_name, cpu_processor_name, encryption_status, encrypted_drives, unencrypted_drives, "
        "os_security.secure_boot_requested_status, os_security.device_guard_status, os_security.device_guard_status, "
        "os_security.device_guard_status, os_security.system_guard_status, os_security.credential_guard_status, "
        "os_security.iommu_protection_status, os_security.secure_boot_enabled_status, "
        "os_security.uefi_memory_protection_status, os_security.virtualization_based_security_status, "
        "os_security.kernel_dma_protection_status, bios_hashes_data.sha256_hash, bios_hashes_data.measurement_type, "
        "bios_id, mount_storage_info.mount_path, form_factor, servicenow_id, owned_by, managed_by, assigned_to, "
        "department, fqdn, used_for, object_guid, object_sid, account_enabled, email, os_service_pack, location, state, "
        " cpu_manufacturer, discovering_by, scan_details.scan_id, scan_details.schedule_id\n\t\t\tAvailable filter "
        "fields that supports range comparisons (>, <, >=, <=): first_seen_timestamp, last_seen_timestamp, "
        "local_ips_count, discoverer_count, confidence, number_of_disk_drives, processor_package_count, "
        "physical_core_count, data_providers_count, logical_core_count, total_disk_space, disk_sizes.disk_space, "
        "total_memory, encrypted_drives_count, unencrypted_drives_count, total_bios_files, average_processor_usage, "
        "average_memory_usage, average_memory_usage_pct, max_processor_usage, max_memory_usage, max_memory_usage_pct, "
        "used_disk_space, used_disk_space_pct, available_disk_space, available_disk_space_pct, "
        "mount_storage_info.used_space, mount_storage_info.available_space, ad_user_account_control, "
        "creation_timestamp, scan_details.scan_date, vulnerability_assessment_date\n\t\t\tAll filter fields and "
        "operations supports negation (!).",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "query_iot_hosts",
    "GET",
    "/discover/queries/iot-hosts/v1",
    "Search for IoT assets in your environment by providing an FQL (Falcon Query Language) filter and paging "
    "details. Returns a set of asset IDs which match the filter criteria.",
    "discover",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "An offset used with the limit parameter to manage pagination of results. On your first "
        " request, don’t provide an offset. On subsequent requests, add previous offset with the previous limit to "
        "continue from that place in the results.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 100,
        "minimum": 1,
        "type": "integer",
        "description": "The number of asset IDs to return in this response (min: 1, max: 100, default: 100). "
        "Use with the offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort assets by their properties. A single sort field is allowed. Common sort options "
        "include:\n\n<ul><li>hostname|asc</li><li>product_type_desc|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter assets using an FQL query. Common filter options include:<ul><li>entity_type:'m "
        "anaged'</li><li>product_type_desc:'Workstation'</li><li>platform_name:'Windows'</li><li>last_seen_timestamp:>' "
        "now-7d'</li></ul>\n\t\t\tAvailable filter fields that support exact match: device_family, device_class, "
        "device_type, device_mode, business_criticality, line_of_business, virtual_zone, subnet, purdue_level, vlan, "
        "local_ip_addresses, mac_addresses, physical_connections_count, data_providers, local_ips_count, "
        "network_interfaces.local_ip, classification\n\t\t\tAvailable filter fields that supports wildcard (*): "
        "device_family, device_class, device_type, device_mode, business_criticality, line_of_business, virtual_zone, "
        "subnet, purdue_level, vlan, local_ip_addresses, mac_addresses, data_providers\n\t\t\tAvailable filter fields "
        "that supports range comparisons (>, <, >=, <=): physical_connections_count, local_ips_count\n\t\t\tAll filter "
        "fields and operations supports negation (!).",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "query_iot_hostsV2",
    "GET",
    "/discover/queries/iot-hosts/v2",
    "Search for IoT assets in your environment by providing an FQL (Falcon Query Language) filter and paging "
    "details. Returns a set of asset IDs which match the filter criteria.",
    "discover",
    [
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an after token. On subsequent requests, provide the after token from the "
        "previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "maximum": 100,
        "minimum": 1,
        "type": "integer",
        "description": "The number of asset IDs to return in this response (min: 1, max: 100, default: 100). "
        "Use with the after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort assets by their properties. A single sort field is allowed. Common sort options "
        "include:\n\n<ul><li>hostname|asc</li><li>product_type_desc|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter assets using an FQL query. Common filter options include:<ul><li>entity_type:'m "
        "anaged'</li><li>product_type_desc:'Workstation'</li><li>platform_name:'Windows'</li><li>last_seen_timestamp:>' "
        "now-7d'</li></ul>\n\t\t\tAvailable filter fields that support exact match: device_family, device_class, "
        "device_type, device_mode, business_criticality, line_of_business, virtual_zone, subnet, purdue_level, vlan, "
        "local_ip_addresses, mac_addresses, physical_connections_count, data_providers\n\t\t\tAvailable filter fields "
        "that supports wildcard (*): device_family, device_class, device_type, device_mode, business_criticality, "
        "line_of_business, virtual_zone, subnet, purdue_level, vlan, local_ip_addresses, mac_addresses, "
        "data_providers\n\t\t\tAvailable filter fields that supports range comparisons (>, <, >=, <=): "
        "physical_connections_count\n\t\t\tAll filter fields and operations supports negation (!).",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "query_logins",
    "GET",
    "/discover/queries/logins/v1",
    "Search for logins in your environment by providing an FQL (Falcon Query Language) filter and paging "
    "details. Returns a set of login IDs which match the filter criteria.",
    "discover",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "An offset used with the limit parameter to manage pagination of results. On your first "
        " request, don’t provide an offset. On subsequent requests, add previous offset with the previous limit to "
        "continue from that place in the results.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 100,
        "minimum": 1,
        "type": "integer",
        "description": "The number of login IDs to return in this response (min: 1, max: 100, default: 100). "
        "Use with the offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort logins by their properties. A single sort field is allowed. Common sort options "
        "include:\n\n<ul><li>account_name|asc</li><li>login_timestamp|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter logins using an FQL query. Common filter options include:<ul><li>account_type:' "
        "Local'</li><li>login_type:'Interactive'</li><li>first_seen_timestamp:<'now-"
        "7d'</li><li>admin_privileges:'No'</li></ul>\n\t\t\tAvailable filter fields that support exact match: id, cid, "
        "login_status, account_id, host_id, user_sid, aid, account_name, username, hostname, account_type, login_type, "
        "login_timestamp, login_domain, admin_privileges, local_admin_privileges, local_ip, remote_ip, host_country, "
        "host_city, is_suspicious, failure_description, login_event_count, aggregation_time_interval\n\t\t\tAvailable "
        "filter fields that supports wildcard (*): id, cid, login_status, account_id, host_id, user_sid, aid, "
        "account_name, username, hostname, account_type, login_type, login_domain, admin_privileges, "
        "local_admin_privileges, local_ip, remote_ip, host_country, host_city, failure_description, "
        "aggregation_time_interval\n\t\t\tAvailable filter fields that supports range comparisons (>, <, >=, <=): "
        "login_timestamp, login_event_count\n\t\t\tAll filter fields and operations supports negation (!).",
        "name": "filter",
        "in": "query"
      }
    ]
  ]
]
