from datetime import datetime

from pycti import OpenCTIConnectorHelper


def start_work(helper: OpenCTIConnectorHelper, logger, work_name) -> str:
    logger.info(
        "[WORKS] Starting new work...",
    )
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"VulnCheck {work_name} run @{now}"
    return helper.api.work.initiate_work(helper.connect_id, message)


def send_bundle(helper: OpenCTIConnectorHelper, logger, stix_objects, work_id) -> None:
    logger.debug("[WORKS] Bundling objects")
    bundle = helper.stix2_create_bundle(stix_objects)
    if bundle is not None:
        bundles_sent = helper.send_stix2_bundle(bundle, work_id=work_id)
        logger.info("[WORKS] Bundle sent", {"bundles_sent": len(bundles_sent)})


def finish_work(helper: OpenCTIConnectorHelper, logger, work_id, work_name) -> None:
    message = f"[WORKS] Run {work_name} completed"
    helper.api.work.to_processed(work_id, message)
    logger.info(message)
