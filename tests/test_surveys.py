import unittest
from app.application import app
from app.config import OAuthConfig, Config
import json
import requests_mock

with open('tests/test_data/my_surveys.json') as json_data:
    my_surveys_data = json.load(json_data)

with open('tests/test_data/collection_instrument.json') as json_data:
    collection_instrument_data = json.load(json_data)

# print("Test data JSON values are:{}".format(collection_instrument_data))

returned_token = {
    "id": 6,
    "access_token": "a712f0f9-d00d-447a-b143-49984ca3db68",
    "expires_in": 3600,
    "token_type": "Bearer",
    "scope": "",
    "refresh_token": "37ca04d2-6b6c-4854-8e85-f59c2cc7d3de"
}

data_dict_for_jwt_token = {
    'refresh_token': 'e6bde0f6-e123-4dcf-9567-74f4d072fc71',
    'access_token': 'f418d491-eeda-47cb-b3e3-0d5d7b97ee6d',
    'username': 'johndoe',
    'expires_at': '100123456789',
    'scope': '[foo,bar,qnx]'
}

party_id = '3b136c4b-7a14-4904-9e01-13364dd7b972'

collection_instrument_id = '40c7c047-4fb3-4abe-926e-bf19fa2c0a1e'

test_user = {
    'first_name': 'john',
    'last_name': 'doe',
    'email_address': 'testuser2@email.com',
    'email_address_confirm': 'testuser2@email.com',
    'password': 'password',
    'password_confirm': 'password',
    'phone_number': '07717275049',
    'terms_and_conditions': 'Y'
}

data_dict_zero_length = {"": ""}

encoded_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWZyZXNoX3Rva2VuIjoiZTZiZGUwZjYtZTEyMy00ZGNmLTk1NjctNzRmNGQwNzJmYzcxIiwiYWNjZXNzX3Rva2VuIjoiZjQxOGQ0OTEtZWVkYS00N2NiLWIzZTMtMGQ1ZDdiOTdlZTZkIiwidXNlcm5hbWUiOiJqb2huZG9lIiwic2NvcGUiOiJbZm9vLGJhcixxbnhdIiwiZXhwaXJlc19hdCI6IjEwMDEyMzQ1Njc4OSJ9.NhOb7MK_SaaW8wvqwbiiAv5N-oaN8SHYli2Z-NpkJ2A'


class TestApplication(unittest.TestCase):
    """Test case for application endpoints and functionality"""

    def setUp(self):

        self.app = app.test_client()
        self.headers = {
            "Authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoicmluZ3JhbUBub3d3aGVyZS5jb20iLCJ1c2VyX3Njb3BlcyI6WyJjaS5yZWFkIiwiY2kud3JpdGUiXX0.se0BJtNksVtk14aqjp7SvnXzRbEKoqXb8Q5U9VVdy54"  # NOQA
            }

    # Test we get survey data once a user signs in properly. This means we have to mock up OAuth2 server sending a
    # Token. The ras_frontstage will then send a request for data to the API Gateway / Party Service, we Mock this too
    # and reply with survey data. See: https://requests-mock.readthedocs.io/en/latest/response.html
    @requests_mock.mock()
    def test_sign_in_view_survey_data(self, mock_object):
        """Test we display survey data after signing in correctly"""

        # Build mock URL's which are used to provide application data
        url_get_token = OAuthConfig.ONS_OAUTH_PROTOCOL + OAuthConfig.ONS_OAUTH_SERVER + OAuthConfig.ONS_TOKEN_ENDPOINT
        url_get_survey_data = Config.API_GATEWAY_SURVEYS_URL + 'todo/' + party_id
        url_get_collection_instrument_data = Config.API_GATEWAY_COLLECTION_INSTRUMENT_URL + 'collectioninstrument/id/' + collection_instrument_id

        mock_object.post(url_get_token, status_code=200, json=returned_token)
        mock_object.get(url_get_survey_data, status_code=200, json=my_surveys_data)
        mock_object.get(url_get_collection_instrument_data, status_code=200, json=collection_instrument_data)

        response = self.app.post('/sign-in', data={'username': 'testuser@email.com', 'password': 'password'}, headers=self.headers)

        # Our system should check the response data.
        self.assertEqual(response.status_code, 302)
        self.assertTrue(bytes('You should be redirected automatically to target URL', encoding='UTF-8') in response.data)

        response = self.app.get('/surveys/', data={}, headers=self.headers)

        # There should be the correct tabs
        self.assertTrue(bytes('SURVEY_TODO_TAB', encoding='UTF-8') in response.data)
        self.assertTrue(bytes('SURVEY_HISTORY_TAB', encoding='UTF-8') in response.data)
        self.assertTrue(bytes('SURVEY_MESSAGES_TAB', encoding='UTF-8') in response.data)

        # There should be the correct column headings
        self.assertTrue(bytes('SURVEY_COLUMN_HEADING', encoding='UTF-8') in response.data)
        self.assertTrue(bytes('PERIOD_COVERED_COLUMN_HEADING', encoding='UTF-8') in response.data)
        self.assertTrue(bytes('SUBMIT_BY_COLUMN_HEADING', encoding='UTF-8') in response.data)
        self.assertTrue(bytes('STATUS_COLUMN_HEADING', encoding='UTF-8') in response.data)

        # There should be the correct data in the table row
        self.assertTrue(bytes(my_surveys_data['rows'][0]['businessData']['businessRef'], encoding='UTF-8') in response.data)
        self.assertTrue(bytes(my_surveys_data['rows'][0]['surveyData']['longName'], encoding='UTF-8') in response.data)
        self.assertTrue(bytes(my_surveys_data['rows'][0]['businessData']['name'], encoding='UTF-8') in response.data)
        self.assertTrue(bytes(my_surveys_data['rows'][0]['businessData']['businessRef'], encoding='UTF-8') in response.data)

        # TODO Check the status
        # self.assertTrue(bytes(my_surveys_data['rows'][0]['status'], encoding='UTF-8') in response.data)
        # self.assertTrue(bytes('not started', encoding='UTF-8') in response.data)

        # There should be a single Access Survey button
        self.assertTrue(bytes('ACCESS_SURVEY_BUTTON_1', encoding='UTF-8') in response.data)
        self.assertFalse(bytes('ACCESS_SURVEY_BUTTON_2', encoding='UTF-8') in response.data)

        survey_params = {
            'case_id': '7bc5d41b-0549-40b3-ba76-42f6d4cf3fdb',
            'collection_instrument_id': collection_instrument_id
        }

        response = self.app.get('/surveys/access_survey', headers=self.headers, query_string=survey_params)
        # print("The response data is: {}".format(response.data))

        # There should be a Download button
        self.assertTrue(bytes('DOWNLOAD_SURVEY_BUTTON', encoding='UTF-8') in response.data)

        # There should be an Upload button
        self.assertTrue(bytes('UPLOAD_SURVEY_BUTTON', encoding='UTF-8') in response.data)