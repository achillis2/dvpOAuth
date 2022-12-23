import requests
import json
import sys, os
import logging

from functools import wraps
from error import AuthClientError, MissingTokenError

# config = json.load(open("config"))


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

py_handler = logging.FileHandler(f"{__name__}.log", mode='w')
py_formatter = logging.Formatter("%(name)s %(asctime)s %(levelname)s %(message)s")

py_handler.setFormatter(py_formatter)
logger.addHandler(py_handler)


def singleton(cls):
    @wraps(cls)
    def wrapper(*args, **kwargs):
        if not wrapper.instance:
            wrapper.instance = cls(*args, **kwargs)
        return wrapper.instance

    wrapper.instance = None
    return wrapper


def request_new_token():
    session = requests.Session()
    session.proxies = {
        "http": os.environ['QUOTAGUARDSTATIC_URL'], 
        "https": os.environ['QUOTAGUARDSTATIC_URL']
    }

    my_headers = {
          'Content-Type': 'application/x-www-form-urlencoded', 
          }
    params = {'grant_type': 'client_credentials'}

    resp = session.post(
              os.environ['Authentication'],
              params = params,
              headers = my_headers, 
              data = {
                  'client_id':	os.environ['client_id'],
                  'client_secret':	os.environ['client_secret']
              }
          )
    
    a = json.loads(resp.content)
    print(a)
    token = a['access_token']
    return session, token


@singleton
class DVPOAuth:
    '''OAuth API for dvp app'''
    def __init__(self, token = None, session = None):
        self.token = token
        self.session = session
        

    ''' class decorator '''
    def _renew_token(foo):
        ''' private decorator '''
        def wrapper(self, *args, **kwargs):
            try:
                # print(f'token : {self.token}')
                logger.info(f'Existing token : {self.token}')
                return foo(self, *args, **kwargs)
            except (MissingTokenError, AuthClientError) as e:
                self.session, self.token = request_new_token()
                logger.info(f'New token : {self.token}')
                # print(f'token : {self.token}')
                return foo(self, *args, **kwargs)
        return wrapper
        
    @_renew_token
    def check_eligibility(self, account = None):
        if not self.token: raise MissingTokenError

        auth = 'Bearer '+ self.token
        eligibility_params = {
            'ContractAccountID': "\'" + account + "\'",
            'DUNSNumber': "\'" + os.environ['DUNSNumber'] + "\'",
            '$format': 'json'
        }

        resp_query1 = self.session.get(
            os.environ["Eligibility"],
            params=eligibility_params,
            headers={'Authorization': auth}
        )

        print(resp_query1.status_code)
        print(resp_query1.content)
        logger.info(f'Eligibiity status code : {resp_query1.status_code}')

        if resp_query1.status_code == 401:
            logger.exception("Eligibility 401 error.")
            raise AuthClientError
        
