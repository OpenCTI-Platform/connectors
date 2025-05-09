# TODO:    Scenario Outline: At the first start of the connector use GTI_IMPORT_START_DATE as origin date.
# TODO:    Scenario Outline: Fetch will be triggered by 'schedule_iso' based on 'connector_duration_period'.
# TODO:    Scenario Outline: For later call, use the date in the state based on 'last_modification_date'.
# TODO:    Scenario Outline: If GTI_IMPORT_REPORTS is set to False, we shouldn't fetch anything.
# TODO:    Scenario Outline: Need to raise an error in case of invalid GTI_API_KEY.
# TODO:    Scenario Outline: Need to raise an error in case of invalid GTI_API_URL.
# TODO:    Scenario Outline: Should call the endpoint '/collections'.
# TODO:    Scenario Outline: If GTI_REPORT_TYPES is different from 'all' need to craft the query parameter 'filter' accordingly.
# TODO:    Scenario Outline: If GTI_ORIGIN is different from 'all' need to craft the query parameter 'filter' accordingly.
# TODO:    Scenario Outline: If the API response is not a json, need to raise an error.
# TODO:    Scenario Outline: If the API didn't respond, like a network error, should retry a few times.
# TODO:    Scenario Outline: Need to set the query parameter 'limit' to max value authorized '40', so we gonna less trigger pagination.
# TODO:    Scenario Outline: Need to handle pagination using 'cursor' if the 'limit' is reached.
# TODO:    Scenario Outline: When pagination is required 'meta.count' in the response should give us track on how many requests we need to do and have been done.
# TODO:    Scenario Outline: On reports fetching 'last_modification_date' is the targeted date field.
# TODO:    Scenario Outline: Should report, at least in log, how many reports retrieved.
# TODO:    Scenario Outline: Should store somewhere last 'last_modification_date', so later on we have track on the last ingested to not restart from scratch if a crash occurs.
# TODO:    Scenario Outline: Should map gti report response into a pydantic model for ease of use.
# TODO:    Scenario Outline: Need to raise an error if mapping into the pydantic model failed.
# TODO:    Scenario Outline: Send for normalization.
