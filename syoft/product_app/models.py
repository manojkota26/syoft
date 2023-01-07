from django.db import models
from django.contrib.auth.models import AbstractUser


class TimestampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class CustomUser(AbstractUser, TimestampedModel):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('staff', 'Staff'),
    )
    role = models.CharField(max_length=100, choices=ROLE_CHOICES)


class Product(TimestampedModel):
    title = models.CharField(max_length=100)
    description = models.TextField()
    inventory_count = models.PositiveIntegerField()
    is_active = models.BooleanField(default=True)
