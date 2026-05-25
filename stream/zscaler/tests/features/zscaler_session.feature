Feature: Zscaler session handling

  Scenario: Request succeeds with a valid session
    Given a valid authenticated Zscaler session
    When a request is made to Zscaler
    Then the request should succeed without re-authentication

  Scenario: Request auto-reconnects on expired session
    Given a valid authenticated Zscaler session
    When the session expires and a request returns 401
    Then the connector should re-authenticate and succeed