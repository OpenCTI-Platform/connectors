# TODO:    Scenario Outline: Fetch will be triggered by the reports id present in the queue.
# TODO:    Scenario Outline: Should call the endpoint '/collections/{id}/relationships/urls'.
# TODO:    Scenario Outline: If the API response is not a json, need to raise an error.
# TODO:    Scenario Outline: If the API didn't respond, like a network error, should retry a few times.
# TODO:    Scenario Outline: Need to set the query parameter 'limit' to max value authorized '40', so we gonna less trigger pagination.
# TODO:    Scenario Outline: Need to handle pagination using 'cursor' if the 'limit' is reached.
# TODO:    Scenario Outline: When pagination is required 'meta.count' in the response should give us track on how many requests we need to do and have been done.
# TODO:    Scenario Outline: Should report, at least in log, how many urls retrieved.
# TODO:    Scenario Outline: Should map gti urls response into a pydantic model for ease of use.
# TODO:    Scenario Outline: Need to raise an error if mapping into the pydantic model failed.
# TODO:    Scenario Outline: Send for normalization.
