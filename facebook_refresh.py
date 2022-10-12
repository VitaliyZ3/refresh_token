from google.cloud import bigquery
from google.cloud.exceptions import NotFound
import logging
import time
import requests

logger = logging.getLogger()


def get_access_token(access_token, app_id, app_secret, table_ref):
    bigquery_client = bigquery.Client()
    url = 'https://graph.facebook.com/v15.0/debug_token'
    params = {'input_token': access_token, 'access_token': access_token}
    need_to_refresh = False
    validate_resp = requests.get(url, params=params)
    if validate_resp.status_code == 200:
        validation_data = validate_resp.json()['data']
        is_valid = validation_data['is_valid']
        expires_at = validation_data['expires_at']
        data_access_expires_at = validation_data['data_access_expires_at']
        two_weeks = 1209600
        if not is_valid:
            need_to_refresh = True
            logger.info('access token is not valid')
        if expires_at and expires_at - time.time() < two_weeks:
            need_to_refresh = True
            logger.info('there are less than 2 weeks until token expiration')
        if data_access_expires_at and data_access_expires_at - time.time() < two_weeks:
            need_to_refresh = True
            logger.info('there are less than 2 weeks until token data access expiration')
        logger.info(f'is_valid={is_valid} expires_at={expires_at} data_access_expires_at={data_access_expires_at}')
    else:
        logger.info('error while requesting token validation')
        return None
    if need_to_refresh:
        refresh_url = 'https://graph.facebook.com/v15.0/oauth/access_token'
        params = {
            'grant_type': 'fb_exchange_token',
            'client_id': app_id,
            'client_secret': app_secret,
            'fb_exchange_token': access_token
        }
        refresh_resp = requests.get(refresh_url, params=params)
        if refresh_resp.status_code == 200:
            refresh_data = refresh_resp.json()
            token = refresh_data['access_token']
            token_row = {'key': 'user_access_token', 'value': token}
            try:
                query = f"delete from `{table_ref}` where key = 'user_access_token'"
                query_job = bigquery_client.query(query)
                query_job.result()
            except NotFound:
                schema = [
                    bigquery.SchemaField('key', 'STRING'),
                    bigquery.SchemaField('value', 'STRING')
                ]
                logger.info("Table {} is not found".format(table_ref))
                table = bigquery.Table(table_ref, schema=schema)
                table = bigquery_client.create_table(table)
                logger.info("Table {} is created".format(table_ref))

            errors_insert = bigquery_client.insert_rows_json(table_ref, [token_row])
            if not errors_insert:
                logger.info(f"New rows have been added to {table_ref} table")
            else:
                logger.info("Encountered errors while inserting rows: {}".format(errors_insert))
            logger.info('got new token')
            return token
        else:
            logger.info(f'error while requesting token refresh: {refresh_resp.text}')
            return None
    else:
        logger.info('current token is OK')
        return access_token
