Feature: Re-authentication failure

    Scenario: Re-authentication fails
        Given a Zscaler connector with an expired session
        When a request returns 401 and re-authentication fails
        Then the connector should stop retrying and return None