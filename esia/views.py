from esia.client import EsiaAuth
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class EsiaGetUrlView(APIView):
    """Получение ссылки для авторизации есиа."""
    permission_classes = (AllowAny,)

    def get(self, request):
        try:
            esia_auth = EsiaAuth()
            url = esia_auth.get_url()
            return Response(data={'url': url}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'detail': str(e), 'status': 'error'}, status=status.HTTP_400_BAD_REQUEST)


class EsiaGetTokenView(APIView):
    """Поиск пользователя и получение токена для авторизации в системе."""
    permission_classes = (AllowAny,)

    def get(self, request):
        esia_auth = EsiaAuth()
        code = request.GET.get('code')
        state = request.GET.get('state')
        esia_connector = esia_auth.getToken(code, state)
        if esia_connector is not None:
            return Response(data=esia_connector, status=status.HTTP_200_OK)
        else:
            return Response(data={'detail': 'Failed to decrypt code', 'status': 'error'},
                            status=status.HTTP_400_BAD_REQUEST)
