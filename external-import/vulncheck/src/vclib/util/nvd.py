from vclib.util import works

MAX_BUNDLE_SIZE = 200_000


def check_vuln_description(descriptions: list) -> str:
    for d in descriptions:
        if d.lang == "en":
            return d.value
    return ""


def check_size_of_stix_objects(
    helper,
    logger,
    source_name: str,
    stix_objects: list,
    work_id: str,
    work_num: int,
) -> tuple[list, str, int]:
    # PERF: We're intentionally bundling things here in groups to avoid OOM
    if len(stix_objects) > MAX_BUNDLE_SIZE:
        works.finish_work(
            helper=helper,
            logger=logger,
            stix_objects=stix_objects,
            work_id=work_id,
            work_name=source_name,
            work_num=work_num,
        )
        stix_objects = []
        work_num += 1
        work_id = works.start_work(
            helper=helper,
            logger=logger,
            work_name=source_name,
            work_num=work_num,
        )
    return stix_objects, work_id, work_num
