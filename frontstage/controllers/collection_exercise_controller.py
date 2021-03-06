import logging
from datetime import datetime

import requests
from flask import current_app as app
from iso8601 import parse_date, ParseError
from structlog import wrap_logger

from frontstage.exceptions.exceptions import ApiError


logger = wrap_logger(logging.getLogger(__name__))


def get_collection_exercise(collection_exercise_id):
    logger.debug('Attempting to retrieve collection exercise', collection_exercise_id=collection_exercise_id)
    url = f"{app.config['COLLECTION_EXERCISE_URL']}/collectionexercises/{collection_exercise_id}"

    response = requests.get(url, auth=app.config['COLLECTION_EXERCISE_AUTH'])

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        raise ApiError(logger, response,
                       collection_exercise_id=collection_exercise_id,
                       log_level='warning' if response.status_code == 404 else 'exception',
                       message='Failed to retrieve collection exercise')

    logger.debug('Successfully retrieved collection exercise', collection_exercise_id=collection_exercise_id)
    collection_exercise = response.json()

    if collection_exercise['events']:
        collection_exercise['events'] = convert_events_to_new_format(collection_exercise['events'])

    return collection_exercise


def get_collection_exercise_events(collection_exercise_id):
    logger.debug('Attempting to retrieve collection exercise events', collection_exercise_id=collection_exercise_id)
    url = f"{app.config['COLLECTION_EXERCISE_URL']}/collectionexercises/{collection_exercise_id}/events"

    response = requests.get(url, auth=app.config['COLLECTION_EXERCISE_AUTH'])

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        raise ApiError(logger, response,
                       collection_exercise_id=collection_exercise_id,
                       log_level='warning' if response.status_code == 404 else 'exception',
                       message='Failed to retrieve collection exercise events')

    logger.debug('Successfully retrieved collection exercise events', collection_exercise_id=collection_exercise_id)
    return response.json()


def get_collection_exercises_for_survey(survey_id, live_only=None):
    logger.debug('Retrieving collection exercises for survey', survey_id=survey_id)

    if live_only is True:
        url = f"{app.config['COLLECTION_EXERCISE_URL']}/collectionexercises/survey/{survey_id}?liveOnly=true"
    else:
        url = f"{app.config['COLLECTION_EXERCISE_URL']}/collectionexercises/survey/{survey_id}"

    response = requests.get(url, auth=app.config['COLLECTION_EXERCISE_AUTH'])

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        raise ApiError(logger, response,
                       survey_id=survey_id,
                       log_level='warning' if response.status_code == 404 else 'exception',
                       message='Failed to retrieve collection exercises for survey')

    logger.debug("Successfully retrieved collection exercises for survey", survey_id=survey_id)
    collection_exercises = response.json()

    for collection_exercise in collection_exercises:
        if collection_exercise['events']:
            collection_exercise['events'] = convert_events_to_new_format(collection_exercise['events'])

    return collection_exercises


def get_live_collection_exercises_for_survey(survey_id):
    return get_collection_exercises_for_survey(survey_id, True)


def convert_events_to_new_format(events):
    formatted_events = {}
    for event in events:
        try:
            date_time = parse_date(event['timestamp'])
        except ParseError:
            raise ParseError

        formatted_events[event['tag']] = {
            "date": date_time.strftime('%d %b %Y'),
            "month": date_time.strftime('%m'),
            "is_in_future": date_time > parse_date(datetime.now().isoformat())
        }
    return formatted_events
