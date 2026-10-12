"""GraphQL documents of the OpenCTI deployment write-back API.

These documents are sent through ``helper.api.query`` when the installed pycti
release does not ship the deployment helpers yet.
"""

FEATURE_DETECTION_QUERY = """
query DeploymentWriteBackFeatures {
  indicators(first: 1) {
    edges {
      node {
        id
        deployments_count
      }
    }
  }
}
"""

SECURITY_PLATFORM_ADD_MUTATION = """
mutation DeploymentSecurityPlatformAdd($input: SecurityPlatformAddInput!) {
  securityPlatformAdd(input: $input) {
    id
    standard_id
    name
  }
}
"""

REPORT_DEPLOYMENT_MUTATION = """
mutation IndicatorReportDeployment(
  $indicatorId: StixRef!
  $platformId: StixRef!
  $status: IndicatorDeploymentStatus!
  $externalId: String
  $metadata: IndicatorDeploymentMetadataInput
) {
  indicatorReportDeployment(
    indicatorId: $indicatorId
    platformId: $platformId
    status: $status
    externalId: $externalId
    metadata: $metadata
  ) {
    id
  }
}
"""

REPORT_DEPLOYMENTS_MUTATION = """
mutation IndicatorReportDeployments(
  $platformId: StixRef!
  $reports: [IndicatorDeploymentReportInput!]!
) {
  indicatorReportDeployments(platformId: $platformId, reports: $reports) {
    processed
    created
    updated
    unchanged
    errors {
      indicatorId
      message
    }
  }
}
"""

REPORT_HITS_MUTATION = """
mutation IndicatorReportHits(
  $indicatorId: StixRef!
  $platformId: StixRef!
  $count: Int!
  $lastHit: DateTime
  $firstHit: DateTime
  $reportId: String
) {
  indicatorReportHits(
    indicatorId: $indicatorId
    platformId: $platformId
    count: $count
    lastHit: $lastHit
    firstHit: $firstHit
    reportId: $reportId
  ) {
    id
  }
}
"""

DEPLOYMENTS_LIST_QUERY = """
query IndicatorDeploymentsOfPlatform(
  $relationshipTypes: [String]
  $toId: [String]
  $first: Int
  $after: ID
  $filters: FilterGroup
) {
  stixCoreRelationships(
    relationship_type: $relationshipTypes
    toId: $toId
    first: $first
    after: $after
    filters: $filters
  ) {
    edges {
      node {
        id
        deployment_status
        external_id
        revoked
        last_sync_at
        last_hit_at
        hit_count
        from {
          ... on Indicator {
            id
            standard_id
            name
            pattern
            pattern_type
            revoked
            valid_until
            x_opencti_main_observable_type
          }
        }
      }
    }
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
"""
