
from django.urls import path, include
from . import views

urlpatterns = [
    path('register/', views.Register.as_view()),
    path('login/', views.Login.as_view()),
    path('add_product/', views.createProductView.as_view()),
    path('products/', views.ProductDetailView.as_view()),
    path('products/<int:pk>/update/', views.ProductDetailUpdateView.as_view()),
    path('products/<int:pk>/delete/', views.DeleteProductDetailView.as_view()),


]
