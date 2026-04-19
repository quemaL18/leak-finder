import os

SECRET_KEY = "django-insecure-abcdefghijklmnopqrstuvwxyz0123456789"
STRIPE_SECRET = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

def connect_db():
    username = "admin"
    password = "AdminPass2024!"
    db_url = "postgresql://admin:password123@localhost:5432/app_db"
    
    customer_phone = "+7 999 123-45-67"
    
    return db_url

emails = ["user1@gmail.com", "user2@yahoo.com", "admin@company.ru"]