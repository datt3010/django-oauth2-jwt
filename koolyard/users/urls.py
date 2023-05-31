from django.urls import path
from .views import (
    UserList,
    UserDetails,
    GroupList,
    UserLoginView,
    UserRegisterView,
    UserView,
    LogoutView,
    UserListView)

urlpatterns = [
    path('users/', UserList.as_view()),
    path('users/<pk>/', UserDetails.as_view()),
    path('groups', GroupList.as_view()),
    path('login/', UserLoginView.as_view(), name = 'login'),
    path('register/', UserRegisterView.as_view(), name = 'register'),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('listuser/', UserListView.as_view())
]