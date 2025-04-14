from datetime import datetime

from aiohttp import ClientSession
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

class ServiceNowClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.instance_name = self.config.servicenow.instance_name
        self.api_key = self.config.servicenow.api_key
        self.api_version = self.config.servicenow.api_version
        self.api_retry = self.config.servicenow.api_retry
        self.api_backoff = self.config.servicenow.api_backoff.total_seconds()
        self.state_to_exclude = self.config.servicenow.state_to_exclude
        self.severity_to_exclude = self.config.servicenow.severity_to_exclude
        self.priority_to_exclude = self.config.servicenow.priority_to_exclude
        self.import_start_date = self.config.servicenow.import_start_date

        # Define headers in session and update when needed
        self.headers = {
            "x-sn-apikey": self.config.servicenow.api_key,
            "Content-Type": 'application/json'
        }


    def _build_url(self, table_name: str, query_parameters: str):
        """Method for building the url for the api request.

        Args:
            table_name: Table name for the API request.
            query_parameters: A string containing the query parameters for the API request.

        Returns:
            str: The full URL for the API request.
          """
        url = f"https://{self.instance_name}.service-now.com/api/now/{self.api_version}/table/{table_name}?{query_parameters}"
        return url


    async def _list_matched(self, targeted_labels: list[str], table_name: str, query_parameters: str) -> str :
        """ Get the values of the element

        Args:
            targeted_labels(list[str]): labels used to keep the corresponding values.
            table_name(str): table to request
            query_parameters (str): str query to filter data table.

        Returns:
            (str): The concatenated values filtered thanks to labels.
        """
        official_list = await self._request_data(table_name, query_parameters)

        list_matched = [
            item.get("value") for item in official_list.get("result", [])
            if item.get("value") is not None and any(word.lower() in item.get("label", "").lower() for word in targeted_labels)
        ]
        list_matched_convert_to_str = ",".join(list_matched)

        list_unmatched = [
            word for word in targeted_labels
            if not any(word.lower() in item.get("label", "").lower() for item in official_list.get("result", []))
        ]

        if list_unmatched:
            list_available = [item.get("label", "") for item in official_list.get("result", [])]
            self.helper.connector_logger.warning(
                "[FILTERING] When filtering by exclusion, some of your configuration parameters were not taken into "
                "account, see list_unmatched and list_available.",
                {
                    "table_name": table_name,
                    "list_unmatched": list_unmatched,
                    "list_available": list_available,
                    "query_parameters": query_parameters,
                },
            )

        return list_matched_convert_to_str

    async def get_state_to_exclude(self):
        if self.state_to_exclude is None:
            return None
        table_name = "sys_choice"
        query_parameters = (
            "sysparm_query=name=sn_si_incident^element=state"
            "&sysparm_fields=label,value"
        )
        return await self._list_matched(self.state_to_exclude, table_name, query_parameters)

    async def get_severity_to_exclude(self):
        if self.severity_to_exclude is None:
            return None
        table_name = "sys_choice"
        query_parameters = (
            "sysparm_query=name=sn_si_incident^element=severity"
            "&sysparm_fields=label,value"
        )
        return await self._list_matched(self.severity_to_exclude, table_name, query_parameters)

    async def get_priority_to_exclude(self):
        if self.priority_to_exclude is None:
            return None
        table_name = "sys_choice"
        query_parameters = (
            "sysparm_query=name=task^element=priority"
            "&sysparm_fields=label,value"
        )
        return await self._list_matched(self.priority_to_exclude, table_name, query_parameters)

    async def get_security_incidents(
            self,
            state_to_exclude: str | None,
            severity_to_exclude:str | None,
            priority_to_exclude:str | None,
            last_run: str | None,
    ) -> dict:
        table_name = "sn_si_incident"

        # To find all available fields, see ServiceNow's API REST explorer in Table_name "sn_si_incident"
        list_sysparm_fields = [
            "sys_id",
            "number",
            "description",
            "short_description",
            "state",
            "severity",
            "priority",
            "category",
            "subcategory",
            "mitre_malware",
            "mitre_tactic",
            "mitre_technique",
            "mitre_group",
            "mitre_tool",
            "sys_created_on",
            "sys_updated_on",
            "estimated_end",
            "comments_and_work_notes",
        ]
        sysparm_fields = ','.join(list_sysparm_fields)


        sysparm_query = ""
        filters_sysparm_query = []

        if self.import_start_date:
            filters_sysparm_query.append(f"sys_updated_on>{self.import_start_date if not last_run else last_run}")
        if state_to_exclude:
            filters_sysparm_query.append(f"stateNOT IN{state_to_exclude}")
        if severity_to_exclude:
            filters_sysparm_query.append(f"severityNOT IN{severity_to_exclude}")
        if priority_to_exclude:
            filters_sysparm_query.append(f"priorityNOT IN{priority_to_exclude}")

        if len(filters_sysparm_query) != 0 :
            sysparm_query = "^".join(filters_sysparm_query)

        filter_query_parameters = []

        if sysparm_query:
            filter_query_parameters.append(f"sysparm_query={sysparm_query}")

        filter_query_parameters.append("sysparm_display_value=true")
        filter_query_parameters.append("sysparm_exclude_reference_link=true")
        filter_query_parameters.append(f"sysparm_fields={sysparm_fields}")

        query_parameters = "&".join(filter_query_parameters)

        return await self._request_data(table_name, query_parameters)

    async def get_tasks(self, security_incident_id: str):
        table_name = "sn_si_task"

        # To find all available fields, see ServiceNow's API REST explorer in Table_name "sn_si_task"
        list_sysparm_fields = [
            "sys_id",
            "number",
            "due_date",
            "sys_tags",
            "security_tags",
            "short_description",
            "description",
            "comments_and_work_notes",
            "sys_created_on",
            "sys_updated_on",
        ]
        sysparm_fields = ','.join(list_sysparm_fields)

        query_parameters = (
            f"sysparm_query=parent={security_incident_id}"
            "&sysparm_display_value=true"
            "&sysparm_exclude_reference_link=true"
            f"&sysparm_fields={sysparm_fields}"
        )

        return await self._request_data(table_name, query_parameters)

    async def _request_data(self, table_name: str, query_parameters: str):
        url_built = self._build_url(table_name, query_parameters)
        @retry(
            stop=stop_after_attempt(max_attempt_number=self.api_retry),
            wait=wait_exponential_jitter(initial=1, max=self.api_backoff, exp_base=2, jitter=1),
        )
        async def _retry_wrapped():
            async with ClientSession(
                    headers=self.headers, raise_for_status=True
            ) as session:
                async with session.get(url=url_built) as response:
                    return await response.json()
        return await _retry_wrapped()



