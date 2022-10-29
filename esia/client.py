import base64
import json
import uuid

from urllib.parse import urlencode
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import User
from esia.utils import get_timestamp, make_request, sign_criptoprocsp
from pion.settings.config_esia import SETTING_ESIA


class EsiaSettings:
    """
    Настройки подключения к сервису ЕСИА
    """
    def __init__(self):
        self.esia_client_id = SETTING_ESIA.get('esia_client_id', None)
        self.redirect_uri = SETTING_ESIA.get('redirect_uri', None)
        self.certificate_file = SETTING_ESIA.get('certificate_file', None)
        self.private_key_file = SETTING_ESIA.get('private_key_file', None)
        self.esia_service_url = SETTING_ESIA.get('esia_service_url', None)
        self.esia_scope = SETTING_ESIA.get('esia_scope', None)
        self.esia_token_check_key = SETTING_ESIA.get('esia_token_check_key', None)
        self.esia_token_check_key_password = SETTING_ESIA.get('esia_token_check_key_password', None)
        self.criptoprocsp_ip = SETTING_ESIA.get('criptoprocsp_ip', None)
        self.criptoprocsp_thumbprint = SETTING_ESIA.get('criptoprocsp_thumbprint', None)


class EsiaAuth:
    """
    Коннектор для аутентификации ЕСИА
    """
    _ESIA_ISSUER_NAME = 'http://esia.gosuslugi.ru/'
    _AUTHORIZATION_URL = '/aas/oauth2/ac'
    _TOKEN_EXCHANGE_URL = '/aas/oauth2/te'

    def __init__(self):
        self.settings = EsiaSettings()

    def get_url(self, state=None):
        """
        Возвращает URL-адрес, который должен посетить конечный пользователь для авторизации в ЕСИА.
        """
        params_get = {
            'client_id': self.settings.esia_client_id,
            'redirect_uri': self.settings.redirect_uri,
            'scope': self.settings.esia_scope,
            'response_type': 'code',
            'state': state or str(uuid.uuid4()),
            'timestamp': get_timestamp(),
            'access_type': 'offline'
        }
        params = {'client_secret': params_get.get('scope', '') + params_get.get('timestamp', '') + \
                                   params_get.get('client_id', '') + params_get.get('state', ''),
                  'thumbprint': self.settings.criptoprocsp_thumbprint, 'criptoprocsp_ip': self.settings.criptoprocsp_ip}
        params_get['client_secret'] = sign_criptoprocsp(params)
        if len(params_get['client_secret'].split(' ')) == 1:
            return '{base_url}{auth_url}?{params}'.format(base_url=self.settings.esia_service_url,
                                                          auth_url=self._AUTHORIZATION_URL,
                                                          params=urlencode(sorted(params_get.items())))
        else:
            return 'error create url'

    def getToken(self, code, state):
        """
        Получение токена авторизованного пользователя
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'client_secret': '',
            'state': state,
            'redirect_uri': self.settings.redirect_uri,
            'scope': self.settings.esia_scope,
            'timestamp': get_timestamp(),
            'token_type': 'Bearer',
            'refresh_token': state,
        }
        params_get = {'client_secret': self.settings.esia_scope + get_timestamp() +
                                       self.settings.esia_client_id + state,
                      'thumbprint': self.settings.criptoprocsp_thumbprint,
                      'criptoprocsp_ip': self.settings.criptoprocsp_ip}
        params['client_secret'] = sign_criptoprocsp(params_get)
        try:
            if len(params['client_secret'].split(' ')) == 1:
                url = '{base_url}{token_url}'.format(base_url=self.settings.esia_service_url,
                                                     token_url=self._TOKEN_EXCHANGE_URL)
                response_json = make_request(url=url, method='POST', data=params)
                chunks = response_json['access_token'].split('.')
                if len(chunks) > 1:
                    b64 = chunks[1].replace('-', '+').replace('_', '/') + '=='
                    payload = json.loads(base64.b64decode(b64))
                    esia_connector = EsiaInformationConnector(access_token=response_json['access_token'],
                                                              oid=payload['urn:esia:sbj_id'],
                                                              settings=self.settings)
                    # получение информации о пользователи
                    inf = esia_connector.get_person_main_info()
                    filter = {
                        "surname": inf.get("lastName", ""),
                        "name": inf.get("firstName", ""),
                        "patronymic": inf.get("middleName", ""),
                    }
                    obj = User.objects.filter(**filter).first()
                    if obj is not None:
                        if obj.user is not None:
                            refresh = RefreshToken.for_user(obj.user)
                            data = {
                                "refresh": str(refresh),
                                "access": str(refresh.access_token)
                            }
                            update_last_login(None, obj.user)
                            return data
            return None
        except Exception as exp:
            print(exp)
            return None


class EsiaInformationConnector:
    """
    Коннектор для получения информации от сервисов ЕСИА REST.
    """
    def __init__(self, access_token, oid, settings):
        self.token = access_token
        self.oid = oid
        self.settings = settings
        self._rest_base_url = '%s/rs' % settings.esia_service_url

    def esia_request(self, endpoint_url, accept_schema=None):
        """
        Делает запрос к REST-сервису ЕСИА и возвращает ответные данные JSON.
        """
        headers = {
            'Authorization': "Bearer %s" % self.token
        }

        if accept_schema:
            headers['Accept'] = 'application/json; schema="%s"' % accept_schema
        else:
            headers['Accept'] = 'application/json'

        return make_request(url=endpoint_url, headers=headers)

    def get_person_main_info(self, accept_schema=None):
        url = '{base}/prns/{oid}'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_addresses(self, accept_schema=None):
        url = '{base}/prns/{oid}/addrs?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_contacts(self, accept_schema=None):
        url = '{base}/prns/{oid}/ctts?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_documents(self, accept_schema=None):
        url = '{base}/prns/{oid}/docs?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_organizations(self, accept_schema=None):
        url = '{base}/prns/{oid}/roles?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)