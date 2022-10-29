from django.urls import path, include

from esia.views import EsiaGetUrlView, EsiaGetTokenView

urlpatterns = [
    path('get_url/', EsiaGetUrlView.as_view(), name='get_url_esia_authorization'),
    path('get_token/', EsiaGetTokenView.as_view(), name='token_refresh'),
]
