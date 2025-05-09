# TODO:    Main loop for the connector `_process_callback` function
# TODO:    Manage the pipeline for fetching and processing reports and related entities
# TODO:    Retrieve all entities to convert them into bundles and ingest them into the system

# TODO:    Handle the work management of the pipeline

# TODO:    Scenario Outline: If connector_split_work is False init a unique work for the whole ingest jobs.
# TODO:    Scenario Outline: If connector_split_work is True init a work for each bundle.
# TODO:    Scenario Outline: Send STIX2.1 Bundle.
# TODO:    Scenario Outline: Wait for work to finish.
# TODO:    Scenario Outline: Finalize the work by setting the state with 'last_modification_date', so later on we have track on the last ingested to not restart from scratch if a crash occurs.
# TODO:    Scenario Outline: Finalize the work by calling 'to_processed'.
# TODO:    Scenario Outline: If error in work ingest, should finalize it cleanly.
# TODO:    Scenario Outline: If more massive error on the connector, or shutting down, should finalize all remaining work.

