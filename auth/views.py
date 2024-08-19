import os
import requests, uuid, secrets
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.forms.utils import ErrorList
from django.http import HttpResponse
from rest_framework import viewsets, status, generics, pagination
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer, LoginSerializer, CustomUserSerializer
from .forms import LoginForm, SignUpForm
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from rest_framework.exceptions import AuthenticationFailed
from.models import UserData
#from .producer import publishUser
import jwt, datetime

secret = os.environ['JWT_SECRET_KEY']
NOTIFY_URL = "https://phis.fedgen.net" #Notification URL
FRONTEND_URL = "https://fedgen.net"
CONTENT_URL = "https://phis.fedgen.net/content"
ADMIN_URL = "https://phis.fedgen.net/adminPHIS"
AUTHORIZATION = 'Authorization'

def generate_code():
    code = secrets.token_urlsafe(12)
    return str(code)

class CheckAuth(APIView):
    def post(self, request):
        if request.headers['Authorization']:
            token  = request.headers['Authorization']
            if not token:
                raise AuthenticationFailed('Unauthenticated')
            try:
                payload = jwt.decode(token, secret, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed('Unathenticated')
            return payload
        else:
            raise AuthenticationFailed('Unathenticated')

class CheckAdmin(APIView):
    def post(self, request):
        if request.headers['Authorization']:
            token  = request.headers['Authorization']
            if not token:
                raise AuthenticationFailed('Unauthenticated')
            try:
                payload = jwt.decode(token, secret, algorithms=['HS256'])
                if payload['role'] != 'S':
                    raise AuthenticationFailed('Unathenticated')
            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed('Unathenticated')
            return payload
        else:
            raise AuthenticationFailed('Unathenticated')

class CheckToken(APIView):
    def post(self, request):
        if request.headers['Authorization']:
            token  = request.headers['Authorization']
            if not token:
                raise AuthenticationFailed('Unauthenticated')
            try:
                payload = jwt.decode(token, secret, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed('Unathenticated')
        else:
            raise AuthenticationFailed('Unathenticated')

class SignupView(APIView):
    '''
        User Signup API
        /auth/signup
        method: POST
        data: {
            firstname: "",
            lastname: "",
            email: "",
            password: "",
        } 
        Returns signup status
    '''
    def post(self, request):
        token = GenerateToken.post(self, request)
        response = Response()
        message = FRONTEND_URL+"/auth/verify/" + str(token.data['token'])
        notification_data = {
            "url": message,
            "token": secret,
            "to": request.data['email']
        }
        if UserData.objects.filter(email=request.data['email']).first() is None:
            res = requests.post(NOTIFY_URL+'/notify/email.verify', json=notification_data, headers={'Content-Type': 'application/json'})
            
            if res.status_code == 200:
                code = generate_code()
                data = request.data
                data['unique_id'] = code
                serializer = UserSerializer(data=data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                user = UserData.objects.filter(email=request.data['email']).first()

                event_data = {
                    "auth_user_id": str(user.unique_id),
                    "user_role": user.UserRole,
                    "user_email": user.email,
                    "first_name": user.firstname,
                    "last_name": user.lastname
                }
                header = {'Authorization': token.data['token']}
                content_req = requests.post(CONTENT_URL+'/event.user.signup', json=event_data, headers=header)
                if content_req.ok:
                    c = 1
                    admin_req = requests.post(ADMIN_URL + '/event.user.signup', data=event_data, headers=header)   
                    if admin_req.ok:
                        a = 1
                    else:
                        a = 0
                else:
                    admin_req = requests.post(ADMIN_URL + '/event.user.signup', data=event_data, headers=header)   
                    if admin_req.ok:
                        a = 1
                    else:
                        a = 0
                    c = 0 
                
                response.data = {
                    "ok": True,
                    "event": event_data,
                    'message': "Event successful",
                    'c': c,
                    'a': a
                }
                response.status_code = 200
            else:
                response.data = {
                    "ok": False,
                    'message': "Email not sent"
                }
                response.status_code = 400
        else:
            response.data = {
                "ok": False,
                "message": "User already exists"
            }
            response.status_code = 400
        
        #publishUser('user_created', serializer.data)
        return response

class ForgotPasswordLink(APIView):
    """
        Generate a forgot password link
        /auth/forgot.password.link
        Returns a password reset link
    """
    def post(self, request):
        response = Response()
        try:
            email = request.data['email']
            token = GenerateToken.post(self, request)
            message = FRONTEND_URL+"/auth/forgotpwd/" + str(token.data['token'])
            notification_data = {
                "url": message,
                "token": secret,
                "to": request.data['email']
            }
            res = requests.post(NOTIFY_URL+'/notify/reset.password', json=notification_data, headers={'Content-Type': 'application/json'})
            if res.ok:
                response.data = {
                    "ok": True,
                    'message': "Reset link sent to email"
                }
            else:
                response.data = {
                    "ok": False,
                    "message": "Failed to send link. Try again."
                }
        except KeyError:
            response.data = {
                "ok": False,
                "message": "Invalid request"
            }
        return response

class GenerateToken(APIView):
    """
        Generates web token 
        for internal calls only
        Returns a web token
    """
    def post(self, request):
        email = request.data['email']
        payload = {
                'email': email,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                'iat': datetime.datetime.utcnow()
            }

        token = jwt.encode(payload, secret, algorithm='HS256')
        response = Response()
        response.data = {
            "ok": True,
            'token': token
        }
        
        #publishUser('VerLink_created', serializer.data)
        return response
class GenerateOneToken(APIView):
    """
        Generates web token 
        for internal calls only
        Returns a web token
    """
    def post(self, request):
        email = request.data['email']
        payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                'iat': datetime.datetime.utcnow()
            }

        token = jwt.encode(payload, secret, algorithm='HS256')
        response = Response()
        response.data = {
            "ok": True,
            'token': token
        }
        
        #publishUser('VerLink_created', serializer.data)
        return response

class GenerateEmailLink(APIView):
    '''
        Generate email verification link API
        /auth/generate.email.link
        method: POST
        data: {
            email: ""
        }
        
        Returns status: True or False
    ''' 
    def post(self, request):
        response = Response()
        try:
            email = request.data['email']
            if (UserData.objects.filter(email=email, user_verification=1)): #User is already verified
                response.data = {
                    "ok": False,
                    "message": "user is verified"
                }
            else:
                payload = {
                        'email': email,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                        'iat': datetime.datetime.utcnow()
                    }
                
                token = jwt.encode(payload, secret, algorithm='HS256')
                message = FRONTEND_URL+"/auth/verify/" + str(token) 
                notification_data = {
                    "url": message,
                    "token": secret,
                    "to": request.data['email']
                }
                res = requests.post(NOTIFY_URL+'/notify/email.verify', data=notification_data)
                if res.ok:
                    response.data = {
                        "ok": True,
                        'message': 'Verification email has been sent'
                    }
                else:
                    response.data = {
                        "ok": False,
                        "message": "Verification Email failed to send. Please try again."
                    }
        except KeyError:
            response.data = {
                "ok": False,
                "details": "Invalid request"
            }
        #publishUser('VerLink_created', serializer.data)
        return response

class VerifyEmail(APIView):
    """
        Verifies a user's email
        /auth/verify.email
        
        Returns status
    """
    def post(self, request):
        response = Response()
        try:
            token  = request.data['B']
            if not token:
                response.data = {
                    "ok": False,
                    "message": "Unauthenticated"
                }
                return response
            try:
                payload = jwt.decode(token, secret, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                response.data = {
                    "ok": False,
                    "message": "Expired link"
                }
                return response
            user = UserData.objects.get(email=payload['email'])
            if UserData.objects.filter(email=payload['email'], user_verification=0).first():
                user.user_verification = True
                user.save()
                message = True
                response.data = {
                    'user': payload['email'],
                    'ok': message 
                }
            elif UserData.objects.filter(email=payload['email'], user_verification=1).first():
                message = False
                response.data = {
                    'user': payload['email'],
                    'ok': message 
                }
        except KeyError:
            response.data = {
                "ok": False,
                "details": "Invalid response"
            }
        return response

class LoginView(APIView):
    """
    User Login
    /auth/signin
    Returns status and web token
    """
    def post(self, request):
        response = Response()
        try:
            email = request.data['email']
            password = request.data['password']
            user = UserData.objects.filter(email=email).first()
            if user is None:
                response.data = {
                    "ok": False,
                    "message": "User not found"
                }
                return response
            if not user.check_password(password):
                response.data = {
                    "ok": False,
                    "message": "Incorrect password"
                }
                return response
            
            if UserData.objects.filter(email=email, user_verification=0).first():
                response.data = {
                    "ok": False,
                    "message": "no verification"
                }
            elif UserData.objects.get(email=email, user_verification=1, is_active=True):
                payload = {
                    'id': user.unique_id,
                    'role': user.UserRole,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=180),
                    'iat': datetime.datetime.utcnow()
                }
                u = UserData.objects.filter(email=email, user_verification=1, is_active=True).first()
                u.last_login = timezone.now()
                u.save()
                token = jwt.encode(payload, secret, algorithm='HS256')
                response.set_cookie(key='plt', value=token, httponly=True)
                response.data = {
                    "ok": True,
                    "token": token
                }
        except KeyError:
            response.data = {
                "ok": False,
                "details": "Invalid response"
            }
        return response

class LogoutView(APIView):
    """
    Delete user token
    /auth/logout
    Returns True
    """
    def post(self, request):
        response = Response()
        response.delete_cookie('plt')
        response.data = {
            'ok': True
        }
        return response

class UserView(APIView):
    """
        Gets logged in user information
        /auth/user
        Returns JSON with user data
    """
    def get(self, request):
        token = request.headers.get('Authorization')
        response = Response()
        if not token or token is None:
            response.data = {
                "data": {},
                "ok": True,
                "user_role": ""
            }
            response.status_code = 201
        else:
            try:
                payload = jwt.decode(token, secret, algorithms=['HS256'])
                user = UserData.objects.filter(unique_id=payload['id']).first()
                if user is not None:
                    serializer = UserSerializer(user)
                    message = True
                    response.data = {
                        "data": serializer.data,
                        "ok": message,
                        "user_role": user.UserRole
                    }
                    response.status_code = 200
                else:
                    response.data = {
                        "data": {},
                        "ok": True,
                        "user_role": ""
                    }
                    response.status_code = 400
            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed('Unathenticated')
        
        return response
class GetUser(APIView):
    def post(self, request):
        CheckToken.post(self, request)
        response = Response()
        try:
            user = UserData.objects.filter(email=request.data['email']).first()
            if user is not None:
                serializer = UserSerializer(user)
                response.data = {"ok": True, "details": "User exists", "data": serializer.data, "role": user.UserRole}
            else:
                response.data = {"ok": False, "details": "user does not exist"}
        except KeyError:
            response.data = {"ok": False, "details": "Invalid request"}
        
        return response
class UpdateUser(APIView):
    def post(self, request):
        CheckToken.post(self, request)
        response = Response()
        try:
            filter = request.data['filter']
            data = request.data
            if filter == "author":
                user = UserData.objects.filter(email=data['email']).first()
                if user is not None:
                    user.google_scholar = data['google_scholar']
                    user.research_gate = data['research_gate']
                    user.scopus = data['scopus']
                    user.pub_med = data['pub_med']
                    user.capic_status = data['capic_status']
                    user.save()
                    response.data = {"ok": True, "details": "data updated"}
                    response.status_code = 200
                else:
                    response.data = {"ok": False, "details": "not found"}
                    response.status_code = 404
            else:
                response.data = {"ok": False, "details": "invalid request"}
                response.status_code = 400
        except KeyError:
            response.data = {"ok": False, "details": "invalid request"}
            response.status_code = 400
        return response

class AssignRole(APIView):
    def post(self, request):
        payload = CheckAuth.post(self, request)
        response = Response()
        user = UserData.objects.filter(email=request.data['user_email']).first()
        if user is not None and payload['role'] == "S":
            user.UserRole = request.data['user_role']
            user.save()
            response.data = {
                "ok": True,
                "details": "User role changed"
            }
        else:
            response.data = {
                "ok": False,
                "details": "User does not exist"
            }
        return response
class SuspendUser(APIView):
    def post(self, request):
        payload = CheckAuth.post(self, request)
        response = Response()
        user = UserData.objects.filter(email=request.data['user_email'], unique_id=request.data['user_id']).first()
        if user is not None and payload['role'] == 'S':
            user.is_active = False
            response.data = {
                "ok": True,
                "details": "User suspended"
            }
        else:
            response.data = {
                "ok": False,
                "details": "User does not exist"
            }
        return response
class ForgotPassword(APIView):
    """
        Change user password.
        Requires token
        /auth/forgot.password
        Returns status
    """
    def post(self, request):
        response = Response()
        try:
            password = request.data['password']
            token  = request.data['id']
            if not token:
                response.data = {
                    "ok": False,
                    "message": "Unauthorized access"
                }
                return response
            try:
                payload = jwt.decode(token, secret, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                response.data = {
                    "ok": False,
                    "message": "Expired link"
                }
                return response
            
            user = UserData.objects.filter(email=payload['email']).first()
            user.set_password(password)
            user.save()
            message = True
            response.data= {
                "ok": message
            }
        except KeyError:
            response.data = {
                "ok": False,
                "details": "Invalid request"
            }
        return response
        

class ChangePassword(APIView):
    """
        Allows user to change password
        requires user token
        /auth/change.password
        Returns status
    """
    def post(self, request):
        response = Response()
        try:
            password = request.data['password']
            payload = CheckAuth.post(self, request)
            user = UserData.objects.filter(unique_id=payload['id']).first()
            if not user.check_password(password):
                response.data = {
                    "ok": False,
                    "message": "Incorrect password"
                }
            else:
                user.set_password(request.data['new_password'])
                user.save()
                message = True
                response.delete_cookie('jwt')
                response.data= {
                    'ok': True,
                    "message": "Password changed"
                }
        except KeyError:
            response.data = {
                "ok": False,
                "details": "Invalid request"
            }
        return response 

class DeleteUserView(APIView):
    """
        Delete a user from database
        requires admin role
        /auth/delete
        Returns status
    """
    def delete(self, request):
        payload = CheckAuth.post(self, request)
        response = Response()
        try:
            email = request.data['email']
            user_role = payload['role']
            if user_role == 'A':
                if not UserData.objects.filter(email=email):
                    response.data = {
                    'message': 'User does not exist',
                    'user': email
                    }
                else:
                    UserData.objects.filter(email=email).first().delete()
                    response.data = {
                        'message': 'User Deleted!',
                        'user': email
                    }
            else:
                response.data = {
                    "ok": False,
                    "message": "Unauthorized access"
                }
        except KeyError:
            response.data = {
                "ok": False,
                "details": "Invalid request"
            }
        return response

class QueryEmail(APIView):
    """
        Queries database if an email is already registered or verified
        /auth/verify.email
        Returns status
    """
    def post(self, request):
        response = Response()
        try:
            email = request.data['email']
            user = UserData.objects.filter(email=email)
            
            if not user:
                response.data = {
                    "ok": False,
                    'message': 'User does not exist'
                }
            else:
                if (UserData.objects.filter(email=email, user_verification=0)):
                    response.data = {
                        "ok": True,
                        'message': 'User is not verified',
                        "verified": False
                    }
                else:
                    response.data = {
                        "ok": True,
                        'message': 'User is verified',
                        "verified": True
                    }
        except KeyError:
            response.data = {
                "ok": False,
                "message": "Invalid request"
            }
        return response

def user_data(user):
    return {
        "unique_id": user.unique_id,
        "firstname": user.firstname,
        "lastname": user.lastname,
        "email": user.email,
        "user_role": user.UserRole,
        "isActive": user.user_verification
    }
class Stats(APIView):
    def get(self, request):
        response = Response()
        CheckAdmin.post(self, request)
        number_users = UserData.objects.all().count()
        number_admin = UserData.objects.filter(UserRole="S").count()
        number_author = UserData.objects.filter(UserRole="A").count()
        number_public = UserData.objects.filter(UserRole="P").count()
        number_reviewer = UserData.objects.filter(UserRole="R").count()
        stats = [
            {
                "name": "Users",
                "number": number_users
            },
            {
                "name": "Admins",
                "number": number_admin
            },
            {
                "name": "Authors",
                "number": number_author
            },
            {
                "name": "Public Users",
                "number": number_public
            },
            {
                "name": "Reviewers",
                "number": number_reviewer
            },
        ]
        response.data = {
            "ok": True,
            "object": "Stat",
            "stats": stats
        }
        response.status_code = 200

        return response

class CustomResponsePagination(pagination.PageNumberPagination):
    page_size = 10
    max_page_size = 50
    
    def get_paginated_response(self, data):
        count = self.page.paginator.count
        if count % self.page_size != 0:
            self.last_page = (count // self.page_size) + 1
        elif count % self.page_size == 0:
            self.last_page = count / self.page_size

        return Response({
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': self.page.paginator.count,
            'results': data,
            'pages': {
                'next_page': self.page.next_page_number() if self.get_next_link() else None,
                'current_page': self.page.number,
                'previous_page': self.page.previous_page_number() if self.get_previous_link() else None,
                'last_page': self.last_page
            }
        })

class Users(generics.ListAPIView):
    serializer_class = CustomUserSerializer
    pagination_class = CustomResponsePagination

    def get_queryset(self):
        CheckAdmin.post(self, self.request)
        sort = self.request.query_params.get('sort')
        
        if sort is not None:
            return UserData.objects.all().order_by(sort)
        else:
            return UserData.objects.all()

class Search(generics.ListAPIView):
    serializer_class = CustomUserSerializer
    pagination_class = CustomResponsePagination

    def get_queryset(self):
        CheckAdmin.post(self, self.request)
        option = self.request.query_params.get('filter')
        query = self.request.query_params.get('query')
        sort = self.request.query_params.get('sort')

        
        if option == 'email':
            queries = UserData.objects.filter(email__icontains=query)
        elif option == 'firstname':
            queries = UserData.objects.filter(firstname__icontains=query)
        elif option == 'lastname':
            queries = UserData.objects.filter(firstname__icontains=query)
        elif option == 'role':
            queries = UserData.objects.filter(UserRole=query)
        else:
            queries = UserData.objects.all()
        
        if sort is not None:
            return queries.order_by(sort)
        else:
            return queries

class UserDetailView(APIView):
    def get(self, request, id):
        CheckAdmin.post(self, request)
        user = UserData.objects.filter(unique_id=id).first()
        if user is not None:
            serializer = CustomUserSerializer(user)
            return Response({'ok': True, 'results': serializer.data}, 200)
        else:
            return Response({'ok': False}, 404)
