import functools
import logging

import requests
from flask import current_app as app
from structlog import wrap_logger

from frontstage.exceptions.exceptions import ApiError


logger = wrap_logger(logging.getLogger(__name__))


def get_iac_from_enrolment(enrolment_code):
    logger.debug('Attempting to retrieve IAC')
    url = f"{app.config['IAC_URL']}/iacs/{enrolment_code}"
    response = requests.get(url, auth=app.config['IAC_AUTH'])

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        if response.status_code == 404:
            logger.info('IAC not found', status_code=response.status_code)
            return
        # 401s may include error context in the JSON response
        elif response.status_code != 401:
            raise ApiError(logger, response, message='Failed to retrieve IAC')

    if response.json().get('active') is False:
        logger.info("Invalid IAC used")
        return

    logger.info('Successfully retrieved IAC')
    return response.json()


validate_enrolment_code = functools.partial(get_iac_from_enrolment)
