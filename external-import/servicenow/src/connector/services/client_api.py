from aiohttp import ClientSession
from limiter import Limiter
from tenacity import retry, stop_after_attempt, wait_exponential_jitter


class ServiceNowClient:
    def __init__(self, helper, config):
        """Initialize the client with necessary configurations"""
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

        # Limiter config
        self.rate_limiter = Limiter(
            rate=self.config.servicenow.api_leaky_bucket_rate,
            capacity=self.config.servicenow.api_leaky_bucket_capacity,
            bucket="servicenow",
        )

        # Define headers in session and update when needed
        self.headers = {
            "x-sn-apikey": self.config.servicenow.api_key,
            "Content-Type": "application/json",
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

    async def _list_matched(
        self, targeted_labels: list[str], table_name: str, query_parameters: str
    ) -> str | None:
        """This method queries ServiceNow's "sys_choice" table_name using a parameterized query, with the aim of
        matching labels defined by configuration environment variables (targeted_labels = "state_to_exclude" or
        "severity_to_exclude" or "priority_to_exclude") with those available in ServiceNow (for fields such as state,
        severity and priority).

        If a match is found, the method extracts the associated integer values (ServiceNow internal values) and
        concatenates them into a string, which is used in the query parameters when retrieving security incidents.

        In the event of a failed match, a warning message is recorded in the logs, specifying the unrecognized tags and
        the set of values available in the queried table.

        Args:
            targeted_labels(list[str]): A list of elements that may come from the “state_to_exclude”,
                                        “severity_to_exclude”, “priority_to_exclude” environment variables.
            table_name(str): Name of the ServiceNow table to be requested
            query_parameters (str): Parameters to be included in the request to filter data retrieved from ServiceNow.

        Returns:
            str:  The filtered concatenated values, corresponding to the labels to be excluded.
        """
        official_list = await self._request_data(table_name, query_parameters)

        list_matched = [
            item.get("value")
            for item in official_list.get("result", [])
            if item.get("value") is not None
            and any(
                word.lower() in item.get("label", "").lower()
                for word in targeted_labels
            )
        ]
        list_matched_convert_to_str = ",".join(list_matched) if list_matched else None

        list_unmatched = [
            word
            for word in targeted_labels
            if not any(
                word.lower() in item.get("label", "").lower()
                for item in official_list.get("result", [])
            )
        ]

        if list_unmatched:
            list_available = [
                item.get("label", "") for item in official_list.get("result", [])
            ]
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

    async def get_state_to_exclude(self) -> str | None:
        """Prepares the parameters needed to extract the statuses to be excluded from ServiceNow, according to the
        configuration defined in "state_to_exclude".

        This method defines the target table ("sys_choice") and builds the query parameters to retrieve the names and
        values of the states configured in ServiceNow.

        Returns:
            str | None: A string of numerical values corresponding to excluded states, or "None" if no exclusion is
                        defined.
        """
        if self.state_to_exclude is None:
            return None
        table_name = "sys_choice"
        query_parameters = (
            "sysparm_query=name=sn_si_incident^element=state"
            "&sysparm_fields=label,value"
        )
        return await self._list_matched(
            self.state_to_exclude, table_name, query_parameters
        )

    async def get_severity_to_exclude(self) -> str | None:
        """Prepares the parameters needed to extract the severity to be excluded from ServiceNow, according to the
        configuration defined in "severity_to_exclude".

        This method defines the target table_name ("sys_choice") and builds the query parameters to retrieve the names
        and values of the severity configured in ServiceNow.

        Returns:
            str | None: A string of numerical values corresponding to excluded severity, or "None" if no exclusion is
                        defined.
        """
        if self.severity_to_exclude is None:
            return None
        table_name = "sys_choice"
        query_parameters = (
            "sysparm_query=name=sn_si_incident^element=severity"
            "&sysparm_fields=label,value"
        )
        return await self._list_matched(
            self.severity_to_exclude, table_name, query_parameters
        )

    async def get_priority_to_exclude(self) -> str | None:
        """Prepares the parameters needed to extract the priority to be excluded from ServiceNow, according to the
        configuration defined in "priority_to_exclude".

        This method defines the target table ("sys_choice") and builds the query parameters to retrieve the names and
        values of the priority configured in ServiceNow.

        Returns:
            str | None: A string of numerical values corresponding to excluded severity, or "None" if no exclusion is
                        defined.
        """
        if self.priority_to_exclude is None:
            return None
        table_name = "sys_choice"
        query_parameters = (
            "sysparm_query=name=task^element=priority" "&sysparm_fields=label,value"
        )
        return await self._list_matched(
            self.priority_to_exclude, table_name, query_parameters
        )

    async def get_security_incidents(
        self,
        state_to_exclude: str | None,
        severity_to_exclude: str | None,
        priority_to_exclude: str | None,
        last_run: str | None,
    ) -> dict:
        """Retrieves security incidents from ServiceNow by applying exclusion filters on state, severity, priority and
        last execution date (or "import_start_date" for the first run of the connector).

        This method dynamically builds query parameters to query ServiceNow's "sn_si_incident" table.
        The fields returned are predefined and cover all the metadata required to model a security incident.

        Args:
            state_to_exclude (str | None): Comma-separated status values to be excluded.
            severity_to_exclude (str | None): Severity values to exclude, separated by commas.
            priority_to_exclude (str | None): Comma-separated priority values to exclude.
            last_run (str | None): Datetime of last connector run (in ISO format).
        Returns:
            dict: The results returned by the ServiceNow API containing the list of Security Incident Responses (SIR).
        """
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
            "security_tags",
            "sys_tags",
            "contact_type",
            "alert_sensor",
        ]
        sysparm_fields = ",".join(list_sysparm_fields)

        sysparm_query = ""
        filters_sysparm_query = []

        if self.import_start_date:
            filters_sysparm_query.append(
                f"sys_updated_on>{self.import_start_date if not last_run else last_run}"
            )
        if state_to_exclude:
            filters_sysparm_query.append(f"stateNOT IN{state_to_exclude}")
        if severity_to_exclude:
            filters_sysparm_query.append(f"severityNOT IN{severity_to_exclude}")
        if priority_to_exclude:
            filters_sysparm_query.append(f"priorityNOT IN{priority_to_exclude}")

        if len(filters_sysparm_query) != 0:
            sysparm_query = "^".join(filters_sysparm_query)

        filter_query_parameters = []

        if sysparm_query:
            filter_query_parameters.append(f"sysparm_query={sysparm_query}")

        filter_query_parameters.append("sysparm_display_value=true")
        filter_query_parameters.append("sysparm_exclude_reference_link=true")
        filter_query_parameters.append(f"sysparm_fields={sysparm_fields}")

        query_parameters = "&".join(filter_query_parameters)

        return await self._request_data(table_name, query_parameters)

    async def get_observables(self, sys_id: str) -> dict:
        """The query retrieves observables associated with a task or security incident sys_id and includes a selection
        of relevant fields "sysparm_fields" associated with each observable. This is not an exhaustive list of fields.
        To view all of them, please refer to the ServiceNow REST API Explorer with "sn_ti_m2m_task_observable" table.

        Args:
            sys_id (str): The unique identifier of the task or security incident whose observables are to be retrieved.
        Returns:
            dict: The results returned by the ServiceNow API containing the list of observables associated with the
                  specified security incident or task.
        """
        table_name = "sn_ti_m2m_task_observable"

        list_sysparm_fields = [
            "observable.sys_id",
            "observable.security_tags",
            "observable.sys_tags",
            "observable.value",
            "observable.type",
            "observable.finding",
            "observable.sys_created_on",
            "observable.sys_updated_on",
            "observable.notes",
        ]
        sysparm_fields = ",".join(list_sysparm_fields)

        query_parameters = (
            f"sysparm_query=task={sys_id}"
            "&sysparm_display_value=true"
            "&sysparm_exclude_reference_link=true"
            f"&sysparm_fields={sysparm_fields}"
        )
        return await self._request_data(table_name, query_parameters)

    async def get_tasks(self, security_incident_id: str) -> dict:
        """Retrieves tasks associated with a specific security incident from ServiceNow.
        This method queries the "sn_si_task" table_name, filtering results by the identifier ("sys_id") of the parent
        security incident ("security_incident_id"). It retrieves a set of predefined fields for each task.

        Args:
            security_incident_id (str): The ServiceNow identifier ("sys_id") of the security incident for which the
                                        tasks are to be retrieved.
        Returns:
             dict: The results returned by the ServiceNow API containing the list of tasks associated with the
                   specified security incident.
        """
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
        sysparm_fields = ",".join(list_sysparm_fields)

        query_parameters = (
            f"sysparm_query=parent={security_incident_id}"
            "&sysparm_display_value=true"
            "&sysparm_exclude_reference_link=true"
            f"&sysparm_fields={sysparm_fields}"
        )

        return await self._request_data(table_name, query_parameters)

    async def _request_data(self, table_name: str, query_parameters: str):
        """Asynchronously sends a GET request to the specified ServiceNow table using the provided query parameters.
        Includes automatic retry logic with exponential backoff and jitter in case of transient failures.

        Args:
            table_name (str): The name of the ServiceNow table to query.
            query_parameters (str): The encoded query string to be appended to the request URL.
        Returns:
            dict: The JSON response data from the ServiceNow API.
        """
        url_built = self._build_url(table_name, query_parameters)

        @retry(
            stop=stop_after_attempt(max_attempt_number=self.api_retry),
            wait=wait_exponential_jitter(
                initial=1, max=self.api_backoff, exp_base=2, jitter=1
            ),
        )
        async def _retry_wrapped():
            async with ClientSession(
                headers=self.headers,
                raise_for_status=True,
                trust_env=True,
            ) as session:
                async with session.get(url=url_built) as response:
                    return await response.json()

        async with self.rate_limiter:
            return await _retry_wrapped()
