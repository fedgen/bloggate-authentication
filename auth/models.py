from django.db import models
from django.contrib.auth.models import AbstractUser



# Create your models here.
class UserData(AbstractUser):
    def generate_code():
        code = secrets.token_urlsafe(12)
        return str(code)
    
    PUBLIC = 'P'
    AUTHOR = 'A'
    REVIEWER = 'R'
    ADMIN = 'S'
    
    USER_ROLES = [
        (PUBLIC, 'public'),
        (AUTHOR, 'author'),
        (REVIEWER, 'reviewer'),
        (ADMIN, 'admin')  
    ]
    
    username = None
    unique_id = models.CharField(max_length=20, unique=True)
    password = models.CharField(max_length=200)
    email = models.EmailField(max_length=100, unique=True)
    firstname = models.CharField(max_length=20)
    lastname = models.CharField(max_length=20)
    UserRole = models.CharField(max_length=2, choices=USER_ROLES, default=PUBLIC)
    user_verification = models.BooleanField(default=False)
    google_scholar = models.URLField(max_length=200, null=True, unique=True)
    research_gate = models.URLField(max_length=200, null=True, unique=True)
    scopus = models.URLField(max_length=200, null=True, unique=True)
    pub_med = models.URLField(max_length=200, null=True, unique=True)
    capic_status = models.CharField(max_length=100, blank=True)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []