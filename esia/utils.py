import json
import datetime
import pytz
import requests
import re

from esia.exceptions import IncorrectJsonError, HttpError


def make_request(url, method='GET', headers=None, data=None):
    """
    Делает запрос по указанному URL-адресу и возвращает проанализированный ответ JSON
    :type url: str
    :type method: str
    :type headers: dict or None
    :type data: dict or None
    :rtype: dict
    :raises HttpError: if requests.HTTPError occurs
    :raises IncorrectJsonError: если данные ответа не могут быть преобразованы в JSON
    """
    try:
        response = requests.request(method, url, headers=headers, data=data)
        response.raise_for_status()
        return json.loads(response.content.decode())
    except requests.HTTPError as e:
        raise HttpError(e)
    except ValueError as e:
        raise IncorrectJsonError(e)


def sign_criptoprocsp(params):
    """
    Получение зашифрованных данных от Крипто ПРО
    :param params: данные конфигурации
    :return: зашифрованые данные в формате строки
    """
    params_get = {'comand': 'signf',
                  'thumbprint': params.get('thumbprint', ''),
                  'message': params.get('client_secret', '')}
    response = requests.get(params.get('criptoprocsp_ip', ''), params=params_get)
    sign = re.sub("^\s+|\n|\r|\s+$", '', response.text)
    return sign


def get_timestamp():
    return datetime.datetime.now(pytz.utc).strftime('%Y.%m.%d %H:%M:%S %z').strip()
