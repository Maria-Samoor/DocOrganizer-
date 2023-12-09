from django.urls import path,include
# from DocOrgnizer.views import dashboard,register,CustomerSignUpView,DeliverySignUpView, about, signup, StoreSignUpView,CustomPasswordResetView, PasswordResetDoneView, userprofile#,SignUpView,StoreSignUpView,DeliverySignUpView
from DocOrgnizer.views import  sign_up , home_view, about_us ,activate  , forgot_password, reset_password,login_view

urlpatterns = [
    # path("", dashboard, name="dashboard"),
    # path('accounts/signup/customer/', CustomerSignUpView, name="customer_signup"),
    # path("accounts/signup/", signup , name="signup"),
    # path('accounts/signup/store/', StoreSignUpView, name="store_signup"),
    # path('accounts/signup/delivery/', DeliverySignUpView, name="delivery_signup"),
    # path("accounts/resetPassword/",  CustomPasswordResetView.as_view(), name="resetPassword"),
    # path("accounts/resetPassword/done", PasswordResetDoneView.as_view(), name="resetPasswordDone"),
    # path("accounts/", include("django.contrib.auth.urls")),
    # path("accounts/login/userProfile/",userprofile, name="userProfile"),
    # #path('oauth/', include('social_django.urls', namespace="social")),
    # path("register/", register, name="register"),
    # path("about/",about, name="about"),
    #path('',homepage,name='homepage'),
    # urls.py
    path('', home_view, name='home'),
    path('about/', about_us, name='about'),
    path('login/', login_view, name='login'), 
    path('signup/',sign_up,name='signup'),
    path('activate/<uidb64>/<token>', activate, name='activate'),
    path('forgoturpassword/', forgot_password, name='forgoturpassword'),
    path('reseturpassword/<uidb64>/<token>', reset_password, name='reseturpassword'),
    #path('login', login, name='login'),
    #path('logout', logout, name='logout'),
] 

