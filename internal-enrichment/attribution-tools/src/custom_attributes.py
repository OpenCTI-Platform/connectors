# Custom attributes for querying objects with pycti without fetching unnecessary attributes

CUSTOM_ATTRIBUTES = """
    id
    standard_id
    entity_type
    parent_types
    name
"""
CUSTOM_ATTRIBUTES_NO_NAME = """
    id
    standard_id
    entity_type
    parent_types
"""
CUSTOM_ATTRIBUTES_OBSERVABLE = """
    id
    standard_id
    entity_type
    parent_types
    observable_value
"""
CUSTOM_ATTRIBUTES_RELATIONSHIP = """
    id
    standard_id
    entity_type
    parent_types
    relationship_type
    objectMarking {
        edges {
            node {
                id
                standard_id
                entity_type
                definition_type
                created
                modified
                definition
                x_opencti_order
                x_opencti_color
            }
        }
    }
    from {
        ... on BasicObject {
            id
            entity_type
            parent_types
        }
        ... on BasicRelationship {
            id
            entity_type
            parent_types
        }
        ... on StixObject {
            standard_id
            spec_version
            created_at
            updated_at
        }
        ... on AttackPattern {
            name
        }
        ... on Campaign {
            name
        }
        ... on CourseOfAction {
            name
        }
        ... on Individual {
            name
        }
        ... on Organization {
            name
        }
        ... on Sector {
            name
        }
        ... on System {
            name
        }
        ... on Indicator {
            name
        }
        ... on Infrastructure {
            name
        }
        ... on IntrusionSet {
            name
        }
        ... on Position {
            name
        }
        ... on City {
            name
        }
        ... on Country {
            name
        }
        ... on Region {
            name
        }
        ... on Malware {
            name
        }
        ... on ThreatActor {
            name
        }
        ... on Tool {
            name
        }
        ... on Vulnerability {
            name
        }
        ... on Incident {
            name
        }
        ... on Event {
            name
            description
        }
        ... on Channel {
            name
            description
        }
        ... on Narrative {
            name
            description
        }
        ... on Language {
            name
        }
        ... on DataComponent {
            name
            description
        }
        ... on DataSource {
            name
            description
        }
        ... on Case {
            name
        }
        ... on StixCyberObservable {
            observable_value
        }
        ... on StixCoreRelationship {
            standard_id
            spec_version
            created_at
            updated_at
        }
    }
    to {
        ... on BasicObject {
            id
            entity_type
            parent_types
        }
        ... on BasicRelationship {
            id
            entity_type
            parent_types
        }
        ... on StixObject {
            standard_id
            spec_version
            created_at
            updated_at
        }
        ... on AttackPattern {
            name
        }
        ... on Campaign {
            name
        }
        ... on CourseOfAction {
            name
        }
        ... on Individual {
            name
        }
        ... on Organization {
            name
        }
        ... on Sector {
            name
        }
        ... on System {
            name
        }
        ... on Indicator {
            name
        }
        ... on Infrastructure {
            name
        }
        ... on IntrusionSet {
            name
        }
        ... on Position {
            name
        }
        ... on City {
            name
        }
        ... on Country {
            name
        }
        ... on Region {
            name
        }
        ... on Malware {
            name
        }
        ... on ThreatActor {
            name
        }
        ... on Tool {
            name
        }
        ... on Vulnerability {
            name
        }
        ... on Incident {
            name
        }
        ... on Event {
            name
            description
        }
        ... on Channel {
            name
            description
        }
        ... on Narrative {
            name
            description
        }
        ... on Language {
            name
        }
        ... on DataComponent {
            name
            description
        }
        ... on DataSource {
            name
            description
        }
        ... on Case {
            name
        }
        ... on StixCyberObservable {
            observable_value
        }
        ... on StixCoreRelationship {
            standard_id
            spec_version
            created_at
            updated_at
        }
    }
"""