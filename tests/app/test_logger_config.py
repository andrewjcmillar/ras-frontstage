import logging
import os
import unittest

from structlog import wrap_logger

from frontstage.logger_config import logger_initial_config


class TestLoggerConfig(unittest.TestCase):

    def setUp(self):
        if os.environ.get('JSON_INDENT_LOGGING'):
            os.environ.pop('JSON_INDENT_LOGGING')

    def test_success(self):
        os.environ['JSON_INDENT_LOGGING'] = '1'
        logger_initial_config()
        logger = wrap_logger(logging.getLogger())
        with self.assertLogs(level='ERROR') as cm:
            logger.error('Test')
        message = cm[0][0].msg
        self.assertTrue('{\n "event": "Test",\n "level": "error",\n "service": "ras-frontstage"' in message)

    def test_indent_type_error(self):
        logger_initial_config()
        logger = wrap_logger(logging.getLogger())
        with self.assertLogs(level='ERROR') as cm:
            logger.error('Test')
        message = cm[0][0].msg
        self.assertTrue('{"event": "Test", "level": "error", "service": "ras-frontstage"' in message)

    def test_indent_value_error(self):
        os.environ['JSON_INDENT_LOGGING'] = 'abc'
        logger_initial_config()
        logger = wrap_logger(logging.getLogger())
        with self.assertLogs(level='ERROR') as cm:
            logger.error('Test')
        message = cm[0][0].msg
        self.assertTrue('{"event": "Test", "level": "error", "service": "ras-frontstage"' in message)
