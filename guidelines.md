# Save this content to a file
cat > mental-health-bridge-complete-guide.md << 'EOF'
# Mental Health Communication Bridge - Complete Build Guide

## Executive Summary

**What You're Building:** An app that removes barriers for people with depression to get support by enabling their trusted network to proactively reach out when patterns suggest struggle.

**Unique Value:** Unlike mood trackers that isolate users, this facilitates human connection through proactive supporter prompts - the first mental health app designed for supporters to initiate contact, not wait for users to ask.

**Timeline:** 6-8 weeks to fully functional MVP with real users

**Target Impact:** Help people with depression get support without the burden of asking

---

## Table of Contents

1. [Technical Build Guide (Weeks 1-6)](#part-1-technical-build-guide)
2. [Who Benefits Most](#part-2-who-benefits-most)
3. [Getting 100 Users in 10 Days](#part-3-getting-100-users-in-10-days)
4. [20 Target Companies](#part-4-20-target-companies)
5. [Resources & Documentation](#part-5-resources--documentation)

---

## Part 1: Technical Build Guide (6-8 Weeks)

### Week 1: Foundation Setup

#### Day 1-2: Development Environment

**Install Required Software:**
```bash
# 1. Install Python 3.10+
# Download from: https://www.python.org/downloads/

# 2. Install Node.js 18+
# Download from: https://nodejs.org/

# 3. Install PostgreSQL 14+
# Download from: https://www.postgresql.org/download/

# 4. Install Git
# Download from: https://git-scm.com/downloads
```

**Create Project Structure:**
```bash
# Create main project directory
mkdir mental-health-bridge
cd mental-health-bridge

# Initialize Git
git init
git branch -M main

# Create GitHub repo and connect
# Go to github.com → New Repository → "mental-health-bridge"
git remote add origin https://github.com/YOUR_USERNAME/mental-health-bridge.git
```

**Backend Setup (Django):**
```bash
# Create backend directory
mkdir backend
cd backend

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install Django and dependencies
pip install django==4.2.0
pip install djangorestframework==3.14.0
pip install django-cors-headers==4.0.0
pip install psycopg2-binary==2.9.6
pip install djangorestframework-simplejwt==5.2.2
pip install python-dotenv==1.0.0
pip install django-q==1.3.9

# Create requirements.txt
pip freeze > requirements.txt

# Create Django project
django-admin startproject config .

# Create apps
python manage.py startapp accounts
python manage.py startapp checkins
python manage.py startapp support
python manage.py startapp notifications
```

**Frontend Setup (React):**
```bash
# Go back to main directory
cd ..

# Create React app
npx create-react-app frontend

cd frontend

# Install dependencies
npm install react-router-dom@6
npm install axios
npm install date-fns
npm install lucide-react
npm install tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

**Configure Tailwind (frontend/tailwind.config.js):**
```javascript
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
```

**Update frontend/src/index.css:**
```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

#### Day 3-4: Database Setup

**Create PostgreSQL Database:**
```sql
-- Open PostgreSQL command line (psql)
-- Create database
CREATE DATABASE mental_health_bridge;

-- Create user
CREATE USER bridge_user WITH PASSWORD 'your_secure_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE mental_health_bridge TO bridge_user;
ALTER DATABASE mental_health_bridge OWNER TO bridge_user;
```

**Configure Django Settings (backend/config/settings.py):**
```python
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Add to INSTALLED_APPS
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third party
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_q',
    # Your apps
    'accounts',
    'checkins',
    'support',
    'notifications',
]

# Add CORS middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',  # Add this
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# CORS settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
]

# Database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mental_health_bridge',
        'USER': 'bridge_user',
        'PASSWORD': 'your_secure_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

# JWT settings
from datetime import timedelta
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
}

# Django-Q configuration
Q_CLUSTER = {
    'name': 'mental_health_bridge',
    'workers': 4,
    'timeout': 90,
    'retry': 120,
    'queue_limit': 50,
    'bulk': 10,
    'orm': 'default',
}
```

**Create .env file (backend/.env):**
```env
SECRET_KEY=your-django-secret-key-here-generate-with-django
DEBUG=True
DATABASE_URL=postgresql://bridge_user:your_secure_password@localhost:5432/mental_health_bridge
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-specific-password
```

**Run Initial Migrations:**
```bash
cd backend
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

#### Day 5-7: Authentication System

**Create Custom User Model (backend/accounts/models.py):**
```python
from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Make email the login field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name']
    
    def __str__(self):
        return self.email
```

**Update settings.py:**
```python
AUTH_USER_MODEL = 'accounts.User'
```

**Create Serializers (backend/accounts/serializers.py):**
```python
from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'username', 'password')
        
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            password=validated_data['password']
        )
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'username')
        read_only_fields = ('id', 'email')
```

**Create Views (backend/accounts/views.py):**
```python
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer, UserProfileSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile(request):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data)
```

**Create URLs (backend/accounts/urls.py):**
```python
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', views.get_profile, name='profile'),
]
```

**Update main URLs (backend/config/urls.py):**
```python
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),
]
```

**Frontend: Create Auth Context (frontend/src/context/AuthContext.js):**
```javascript
import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    const token = localStorage.getItem('access_token');
    if (token) {
      try {
        const response = await axios.get('http://localhost:8000/api/auth/profile/', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setUser(response.data);
      } catch (error) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
      }
    }
    setLoading(false);
  };

  const login = async (email, password) => {
    try {
      const response = await axios.post('http://localhost:8000/api/auth/login/', {
        email,
        password
      });
      localStorage.setItem('access_token', response.data.access);
      localStorage.setItem('refresh_token', response.data.refresh);
      await checkAuth();
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  };

  const register = async (email, username, firstName, password) => {
    try {
      const response = await axios.post('http://localhost:8000/api/auth/register/', {
        email,
        username,
        first_name: firstName,
        password
      });
      localStorage.setItem('access_token', response.data.access);
      localStorage.setItem('refresh_token', response.data.refresh);
      await checkAuth();
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  };

  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
```

**Frontend: Create Login Page (frontend/src/pages/Login.js):**
```javascript
import React, { useState, useContext } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    const result = await login(email, password);
    if (result.success) {
      navigate('/');
    } else {
      setError('Invalid email or password');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow">
        <h2 className="text-3xl font-bold text-center">Welcome Back</h2>
        {error && (
          <div className="bg-red-50 text-red-600 p-3 rounded">{error}</div>
        )}
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            />
          </div>
          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700"
          >
            Log In
          </button>
        </form>
        <p className="text-center text-sm">
          Don't have an account?{' '}
          <Link to="/register" className="text-blue-600 hover:underline">
            Sign up
          </Link>
        </p>
      </div>
    </div>
  );
}

export default Login;
```

**Frontend: Create Register Page (frontend/src/pages/Register.js):**
```javascript
import React, { useState, useContext } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';

function Register() {
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [firstName, setFirstName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const { register } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    
    const result = await register(email, username, firstName, password);
    if (result.success) {
      navigate('/');
    } else {
      setError('Registration failed. Please try again.');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow">
        <h2 className="text-3xl font-bold text-center">Create Account</h2>
        {error && (
          <div className="bg-red-50 text-red-600 p-3 rounded">{error}</div>
        )}
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700">First Name</label>
            <input
              type="text"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              required
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Confirm Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            />
          </div>
          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700"
          >
            Sign Up
          </button>
        </form>
        <p className="text-center text-sm">
          Already have an account?{' '}
          <Link to="/login" className="text-blue-600 hover:underline">
            Log in
          </Link>
        </p>
      </div>
    </div>
  );
}

export default Register;
```

**Frontend: Update App.js (frontend/src/App.js):**
```javascript
import React, { useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, AuthContext } from './context/AuthContext';
import Login from './pages/Login';
import Register from './pages/Register';
import Home from './pages/Home';
import SupportNetwork from './pages/SupportNetwork';
import History from './pages/History';
import HelpRequest from './pages/HelpRequest';
import Navigation from './components/Navigation';

function PrivateRoute({ children }) {
  const { user, loading } = useContext(AuthContext);
  
  if (loading) return <div>Loading...</div>;
  
  return user ? children : <Navigate to="/login" />;
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="min-h-screen bg-gray-50">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route
              path="/"
              element={
                <PrivateRoute>
                  <Navigation />
                  <Home />
                </PrivateRoute>
              }
            />
            <Route
              path="/support-network"
              element={
                <PrivateRoute>
                  <Navigation />
                  <SupportNetwork />
                </PrivateRoute>
              }
            />
            <Route
              path="/history"
              element={
                <PrivateRoute>
                  <Navigation />
                  <History />
                </PrivateRoute>
              }
            />
            <Route
              path="/help-request"
              element={
                <PrivateRoute>
                  <Navigation />
                  <HelpRequest />
                </PrivateRoute>
              }
            />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
```

### Week 2: Core Features - Mood Check-ins

**Create Models (backend/checkins/models.py):**
```python
from django.db import models
from django.conf import settings
import uuid

class MoodCheckIn(models.Model):
    MOOD_CHOICES = [
        ('good', 'Good'),
        ('neutral', 'Neutral'),
        ('bad', 'Bad'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='checkins')
    date = models.DateField()
    mood = models.CharField(max_length=10, choices=MOOD_CHOICES)
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user', 'date')
        ordering = ['-date']
    
    def __str__(self):
        return f"{self.user.email} - {self.date} - {self.mood}"
```

**Create Serializers (backend/checkins/serializers.py):**
```python
from rest_framework import serializers
from .models import MoodCheckIn

class MoodCheckInSerializer(serializers.ModelSerializer):
    class Meta:
        model = MoodCheckIn
        fields = ('id', 'date', 'mood', 'note', 'created_at')
        read_only_fields = ('id', 'created_at')
    
    def validate(self, data):
        # Ensure user can't check in twice on same day
        user = self.context['request'].user
        date = data.get('date')
        
        if self.instance is None:  # Creating new check-in
            if MoodCheckIn.objects.filter(user=user, date=date).exists():
                raise serializers.ValidationError("You've already checked in today.")
        
        return data
```

**Create Views (backend/checkins/views.py):**
```python
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from datetime import timedelta
from .models import MoodCheckIn
from .serializers import MoodCheckInSerializer

class MoodCheckInViewSet(viewsets.ModelViewSet):
    serializer_class = MoodCheckInSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return MoodCheckIn.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def today(self, request):
        """Check if user has checked in today"""
        today = timezone.now().date()
        try:
            checkin = MoodCheckIn.objects.get(user=request.user, date=today)
            serializer = self.get_serializer(checkin)
            return Response(serializer.data)
        except MoodCheckIn.DoesNotExist:
            return Response({'checked_in': False}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get mood statistics for a period"""
        period = request.query_params.get('period', 'week')
        
        if period == 'week':
            days = 7
        elif period == 'month':
            days = 30
        else:
            days = 7
        
        start_date = timezone.now().date() - timedelta(days=days)
        checkins = self.get_queryset().filter(date__gte=start_date)
        
        stats = {
            'good': checkins.filter(mood='good').count(),
            'neutral': checkins.filter(mood='neutral').count(),
            'bad': checkins.filter(mood='bad').count(),
            'total': checkins.count()
        }
        
        return Response(stats)
```

**Create URLs (backend/checkins/urls.py):**
```python
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'checkins', views.MoodCheckInViewSet, basename='checkin')

urlpatterns = [
    path('', include(router.urls)),
]
```

**Update main URLs (backend/config/urls.py):**
```python
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),
    path('api/', include('checkins.urls')),
]
```

**Run migrations:**
```bash
python manage.py makemigrations
python manage.py migrate
```

**Frontend: Create Navigation Component (frontend/src/components/Navigation.js):**
```javascript
import React, { useContext } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import { Home, Users, History, AlertCircle, LogOut } from 'lucide-react';

function Navigation() {
  const { user, logout } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="bg-white shadow-md">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center space-x-8">
            <Link to="/" className="text-xl font-bold text-blue-600">
              Mental Health Bridge
            </Link>
            <div className="hidden md:flex space-x-4">
              <Link
                to="/"
                className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-gray-100"
              >
                <Home className="w-4 h-4" />
                Home
              </Link>
              <Link
                to="/support-network"
                className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-gray-100"
              >
                <Users className="w-4 h-4" />
                Support Network
              </Link>
              <Link
                to="/history"
                className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-gray-100"
              >
                <History className="w-4 h-4" />
                History
              </Link>
              <Link
                to="/help-request"
                className="flex items-center gap-2 px-3 py-2 rounded-md bg-blue-600 text-white hover:bg-blue-700"
              >
                <AlertCircle className="w-4 h-4" />
                Ask for Help
              </Link>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600">Hi, {user?.first_name}!</span>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-gray-100"
            >
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}

export default Navigation;
```

**Frontend: Create Home Page with Check-in (frontend/src/pages/Home.js):**
```javascript
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ThumbsUp, Meh, ThumbsDown } from 'lucide-react';

function Home() {
  const [selectedMood, setSelectedMood] = useState(null);
  const [note, setNote] = useState('');
  const [checkedIn, setCheckedIn] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkTodayStatus();
  }, []);

  const checkTodayStatus = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await axios.get('http://localhost:8000/api/checkins/today/', {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data.checked_in !== false) {
        setCheckedIn(true);
      }
    } catch (error) {
      console.error('Error checking status:', error);
    }
    setLoading(false);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      const token = localStorage.getItem('access_token');
      await axios.post('http://localhost:8000/api/checkins/', {
        date: new Date().toISOString().split('T')[0],
        mood: selectedMood,
        note: note
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setCheckedIn(true);
      alert('Check-in saved! 💙');
    } catch (error) {
      alert('Error saving check-in');
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <div className="text-xl">Loading...</div>
      </div>
    );
  }

  if (checkedIn) {
    return (
      <div className="max-w-2xl mx-auto p-6 mt-8">
        <div className="bg-white p-8 rounded-lg shadow text-center">
          <div className="text-6xl mb-4">✓</div>
          <h2 className="text-2xl font-bold mb-4">You've checked in today</h2>
          <p className="text-gray-600 mb-6">Thank you for taking care of yourself. Come back tomorrow for your next check-in.</p>
          <div className="space-y-3">
            
              href="/history"
              className="block w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700"
            >
              View Your History
            </a>
            
              href="/support-network"
              className="block w-full bg-gray-200 text-gray-700 py-3 px-4 rounded-md hover:bg-gray-300"
            >
              Manage Support Network
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto p-6 mt-8">
      <div className="bg-white p-8 rounded-lg shadow">
        <h2 className="text-3xl font-bold mb-6 text-center">How are you today?</h2>
        
        <div className="grid grid-cols-3 gap-4 mb-6">
          <button
            onClick={() => setSelectedMood('good')}
            className={`p-6 rounded-lg border-2 transition ${
              selectedMood === 'good' 
                ? 'border-green-500 bg-green-50' 
                : 'border-gray-300 hover:border-green-300'
            }`}
          >
            <ThumbsUp className="w-12 h-12 mx-auto mb-2 text-green-600" />
            <p className="text-center font-medium">Good</p>
          </button>
          
          <button
            onClick={() => setSelectedMood('neutral')}
            className={`p-6 rounded-lg border-2 transition ${
              selectedMood === 'neutral' 
                ? 'border-yellow-500 bg-yellow-50' 
                : 'border-gray-300 hover:border-yellow-300'
            }`}
          >
            <Meh className="w-12 h-12 mx-auto mb-2 text-yellow-600" />
            <p className="text-center font-medium">Neutral</p>
          </button>
          
          <button
            onClick={() => setSelectedMood('bad')}
            className={`p-6 rounded-lg border-2 transition ${
              selectedMood === 'bad' 
                ? 'border-red-500 bg-red-50' 
                : 'border-gray-300 hover:border-red-300'
            }`}
          >
            <ThumbsDown className="w-12 h-12 mx-auto mb-2 text-red-600" />
            <p className="text-center font-medium">Bad</p>
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              How are you feeling? (Optional)
            </label>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              rows="4"
              className="w-full border border-gray-300 rounded-md p-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="You can share more if you'd like..."
            />
          </div>

          <button
            type="submit"
            disabled={!selectedMood}
            className="w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-lg font-medium"
          >
            Save Check-in
          </button>
        </form>
      </div>
    </div>
  );
}

export default Home;
```

### Week 3: Support Network

**Create Models (backend/support/models.py):**
```python
from django.db import models
from django.conf import settings
import uuid

class SupportPerson(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='support_network')
    supporter_name = models.CharField(max_length=100)
    supporter_email = models.EmailField(blank=True, null=True)
    supporter_phone = models.CharField(max_length=20, blank=True, null=True)
    relationship = models.CharField(max_length=50, blank=True)
    can_see_mood_trends = models.BooleanField(default=False)
    can_see_notes = models.BooleanField(default=False)
    proactive_prompts_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.supporter_name} - {self.user.email}"
```

**Create Serializers (backend/support/serializers.py):**
```python
from rest_framework import serializers
from .models import SupportPerson

class SupportPersonSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupportPerson
        fields = '__all__'
        read_only_fields = ('id', 'user', 'created_at')
    
    def validate(self, data):
        # Ensure at least one contact method
        if not data.get('supporter_email') and not data.get('supporter_phone'):
            raise serializers.ValidationError(
                "At least one contact method (email or phone) is required."
            )
        return data
```

**Create Views (backend/support/views.py):**
```python
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import SupportPerson
from .serializers import SupportPersonSerializer

class SupportPersonViewSet(viewsets.ModelViewSet):
    serializer_class = SupportPersonSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return SupportPerson.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
```

**Create URLs (backend/support/urls.py):**
```python
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'support-network', views.SupportPersonViewSet, basename='support')

urlpatterns = [
    path('', include(router.urls)),
]
```

**Update main URLs (backend/config/urls.py):**
```python
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),
    path('api/', include('checkins.urls')),
    path('api/', include('support.urls')),
]
```

**Run migrations:**
```bash
python manage.py makemigrations
python manage.py migrate
```

**Frontend: Support Network Page (frontend/src/pages/SupportNetwork.js):**
```javascript
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Plus, Trash2 } from 'lucide-react';

function SupportNetwork() {
  const [supporters, setSupporters] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    supporter_name: '',
    supporter_email: '',
    supporter_phone: '',
    relationship: '',
    can_see_mood_trends: false,
    can_see_notes: false,
    proactive_prompts_enabled: true,
  });

  useEffect(() => {
    fetchSupporters();
  }, []);

  const fetchSupporters = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await axios.get('http://localhost:8000/api/support-network/', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSupporters(response.data);
    } catch (error) {
      console.error('Error fetching supporters:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.supporter_email && !formData.supporter_phone) {
      alert('Please provide at least one contact method (email or phone)');
      return;
    }
    
    try {
      const token = localStorage.getItem('access_token');
      await axios.post('http://localhost:8000/api/support-network/', formData, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setShowForm(false);
      setFormData({
        supporter_name: '',
        supporter_email: '',
        supporter_phone: '',
        relationship: '',
        can_see_mood_trends: false,
        can_see_notes: false,
        proactive_prompts_enabled: true,
      });
      fetchSupporters();
      alert('Supporter added successfully!');
    } catch (error) {
      alert('Error adding supporter');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Remove this supporter?')) {
      try {
        const token = localStorage.getItem('access_token');
        await axios.delete(`http://localhost:8000/api/support-network/${id}/`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        fetchSupporters();
      } catch (error) {
        alert('Error removing supporter');
      }
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6 mt-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Support Network</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="bg-blue-600 text-white px-4 py-2 rounded-md flex items-center gap-2 hover:bg-blue-700"
        >
          <Plus className="w-4 h-4" />
          Add Supporter
        </button>
      </div>

      {showForm && (
        <div className="bg-white p-6 rounded-lg shadow mb-6">
          <h2 className="text-xl font-bold mb-4">Add New Supporter</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Name *</label>
              <input
                type="text"
                value={formData.supporter_name}
                onChange={(e) => setFormData({...formData, supporter_name: e.target.value})}
                required
                className="w-full border border-gray-300 rounded-md p-2"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Email</label>
              <input
                type="email"
                value={formData.supporter_email}
                onChange={(e) => setFormData({...formData, supporter_email: e.target.value})}
                className="w-full border border-gray-300 rounded-md p-2"
                placeholder="supporter@example.com"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Phone</label>
              <input
                type="tel"
                value={formData.supporter_phone}
                onChange={(e) => setFormData({...formData, supporter_phone: e.target.value})}
                className="w-full border border-gray-300 rounded-md p-2"
                placeholder="+1 (555) 123-4567"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Relationship</label>
              <input
                type="text"
                value={formData.relationship}
                onChange={(e) => setFormData({...formData, relationship: e.target.value})}
                placeholder="e.g., Family, Friend, Therapist"
                className="w-full border border-gray-300 rounded-md p-2"
              />
            </div>

            <div className="space-y-3 pt-4 border-t">
              <p className="font-medium text-sm text-gray-700">Privacy Settings</p>
              
              <label className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={formData.can_see_mood_trends}
                  onChange={(e) => setFormData({...formData, can_see_mood_trends: e.target.checked})}
                  className="w-4 h-4 mt-1"
                />
                <div>
                  <span className="text-sm font-medium">Can see my mood trends</span>
                  <p className="text-xs text-gray-600">They'll see your overall mood patterns over time</p>
                </div>
              </label>

              <label className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={formData.can_see_notes}
                  onChange={(e) => setFormData({...formData, can_see_notes: e.target.checked})}
                  className="w-4 h-4 mt-1"
                />
                <div>
                  <span className="text-sm font-medium">Can see my notes</span>
                  <p className="text-xs text-gray-600">They'll be able to read your daily check-in notes</p>
                </div>
              </label>

              <label className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={formData.proactive_prompts_enabled}
                  onChange={(e) => setFormData({...formData, proactive_prompts_enabled: e.target.checked})}
                  className="w-4 h-4 mt-1"
                />
                <div>
                  <span className="text-sm font-medium">Receive proactive check-in prompts</span>
                  <p className="text-xs text-gray-600">They'll get notified when patterns suggest you might need support</p>
                </div>
              </label>
            </div>

            <div className="flex gap-2 pt-4">
              <button
                type="submit"
                className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700"
              >
                Add Supporter
              </button>
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="bg-gray-300 text-gray-700 px-6 py-2 rounded-md hover:bg-gray-400"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="space-y-4">
        {supporters.length === 0 ? (
          <div className="bg-white p-8 rounded-lg shadow text-center">
            <div className="text-5xl mb-4">👥</div>
            <h3 className="text-xl font-bold mb-2">No supporters added yet</h3>
            <p className="text-gray-600 mb-4">
              Add people you trust who can support you when you need it
            </p>
            <button
              onClick={() => setShowForm(true)}
              className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700"
            >
              Add Your First Supporter
            </button>
          </div>
        ) : (
          supporters.map((supporter) => (
            <div key={supporter.id} className="bg-white p-6 rounded-lg shadow">
              <div className="flex justify-between items-start">
                <div className="flex-grow">
                  <h3 className="text-lg font-bold">{supporter.supporter_name}</h3>
                  {supporter.relationship && (
                    <p className="text-sm text-gray-600">{supporter.relationship}</p>
                  )}
                  <div className="mt-3 space-y-1 text-sm text-gray-600">
                    {supporter.supporter_email && (
                      <p className="flex items-center gap-2">
                        <span>📧</span>
                        {supporter.supporter_email}
                      </p>
                    )}
                    {supporter.supporter_phone && (
                      <p className="flex items-center gap-2">
                        <span>📱</span>
                        {supporter.supporter_phone}
                      </p>
                    )}
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {supporter.can_see_mood_trends && (
                      <span className="text-xs bg-blue-100 text-blue-700 px-3 py-1 rounded-full">
                        Can see mood trends
                      </span>
                    )}
                    {supporter.can_see_notes && (
                      <span className="text-xs bg-purple-100 text-purple-700 px-3 py-1 rounded-full">
                        Can see notes
                      </span>
                    )}
                    {supporter.proactive_prompts_enabled && (
                      <span className="text-xs bg-green-100 text-green-700 px-3 py-1 rounded-full">
                        Proactive prompts enabled
                      </span>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => handleDelete(supporter.id)}
                  className="text-red-600 hover:text-red-800 p-2"
                >
                  <Trash2 className="w-5 h-5" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default SupportNetwork;
```

### Week 4: Proactive Prompts System (CRITICAL FEATURE)

**Create Models (backend/notifications/models.py):**
```python
from django.db import models
from django.conf import settings
import uuid

class ProactivePrompt(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='proactive_prompts')
    trigger_reason = models.CharField(max_length=100)
    pattern_detected = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    dismissed = models.BooleanField(default=False)
    dismissed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.email} - {self.trigger_reason} - {self.created_at}"

class HelpRequest(models.Model):
    REQUEST_TYPES = [
        ('need_company', 'I need company'),
        ('check_in', 'Just check in on me'),
        ('need_talk', 'I need to talk'),
        ('general_support', 'I need support'),
        ('custom', 'Custom message'),
    ]
    
    INITIATED_BY_CHOICES = [
        ('user', 'User'),
        ('system', 'System (Proactive)'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='help_requests')
    supporter = models.ForeignKey('support.SupportPerson', on_delete=models.CASCADE, related_name='help_requests')
    request_type = models.CharField(max_length=50, choices=REQUEST_TYPES)
    message_text = models.TextField()
    ai_generated = models.BooleanField(default=False)
    initiated_by = models.CharField(max_length=20, choices=INITIATED_BY_CHOICES, default='user')
    sent_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-sent_at']
    
    def __str__(self):
        return f"{self.user.email} → {self.supporter.supporter_name} - {self.sent_at}"
```

**Create Pattern Detection Task (backend/notifications/tasks.py):**
```python
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
from accounts.models import User
from checkins.models import MoodCheckIn
from support.models import SupportPerson
from .models import ProactivePrompt

def detect_patterns_for_all_users():
    """Run daily to check all users for patterns"""
    users = User.objects.filter(is_active=True)
    for user in users:
        detect_patterns(user.id)

def detect_patterns(user_id):
    """Detect patterns for a specific user"""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return
    
    recent_checkins = MoodCheckIn.objects.filter(
        user=user
    ).order_by('-date')[:7]
    
    if not recent_checkins:
        return
    
    # Pattern 1: 3+ consecutive bad days
    consecutive_bad = 0
    for checkin in recent_checkins[:5]:
        if checkin.mood == 'bad':
            consecutive_bad += 1
        else:
            break
    
    if consecutive_bad >= 3:
        pattern = {
            'type': 'consecutive_bad_days',
            'severity': 'medium',
            'description': f'Has had {consecutive_bad} difficult days in a row'
        }
        create_and_notify_proactive_prompt(user, pattern)
    
    # Pattern 2: No check-in for 3+ days
    days_since = (timezone.now().date() - recent_checkins[0].date).days
    if days_since >= 3:
        pattern = {
            'type': 'no_checkin_3days',
            'severity': 'high',
            'description': f'Has not checked in for {days_since} days'
        }
        create_and_notify_proactive_prompt(user, pattern)

def create_and_notify_proactive_prompt(user, pattern):
    """Create prompt record and notify supporters"""
    # Don't create duplicate prompts within 3 days
    recent_prompt = ProactivePrompt.objects.filter(
        user=user,
        trigger_reason=pattern['type'],
        created_at__gte=timezone.now() - timedelta(days=3)
    ).first()
    
    if recent_prompt:
        return  # Already notified recently
    
    # Create prompt record
    prompt = ProactivePrompt.objects.create(
        user=user,
        trigger_reason=pattern['type'],
        pattern_detected=pattern['description'],
        severity=pattern['severity']
    )
    
    # Notify supporters
    supporters = SupportPerson.objects.filter(
        user=user,
        proactive_prompts_enabled=True
    )
    
    for supporter in supporters:
        send_proactive_notification(user, supporter, pattern)
    
    print(f"Created proactive prompt for {user.email}: {pattern['description']}")

def send_proactive_notification(user, supporter, pattern):
    """Send email notification to supporter"""
    subject = f"{user.first_name} might need support"
    
    message = f"""Hi {supporter.supporter_name},

{user.first_name}'s recent patterns suggest they might be struggling and could use a check-in.

Pattern detected: {pattern['description']}

What you can do:
- Send a casual text: "Hey, thinking of you. Want to grab coffee?"
- Don't ask "what's wrong" - just offer presence
- No pressure if they're not ready to talk

Research shows that proactive check-ins from trusted people can make a real difference.

{user.first_name} has given you permission to receive these notifications.

💙 Mental Health Bridge

---
If you no longer wish to receive these notifications, please contact {user.first_name}.
    """
    
    # Send email
    if supporter.supporter_email:
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [supporter.supporter_email],
                fail_silently=False,
            )
            print(f"Sent proactive notification to {supporter.supporter_email}")
        except Exception as e:
            print(f"Error sending email to {supporter.supporter_email}: {e}")
```

**Update Django Settings for Email (backend/config/settings.py):**
```python
# Email configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = os.getenv('EMAIL_HOST_USER', 'noreply@mentalhealthbridge.com')
```

**Create Management Command for Pattern Detection (backend/notifications/management/commands/run_pattern_detection.py):**

First create the directories:
```bash
mkdir -p backend/notifications/management/commands
touch backend/notifications/management/__init__.py
touch backend/notifications/management/commands/__init__.py
```

Then create the command file:
```python
from django.core.management.base import BaseCommand
from notifications.tasks import detect_patterns_for_all_users

class Command(BaseCommand):
    help = 'Run pattern detection for all users'

    def handle(self, *args, **options):
        self.stdout.write('Running pattern detection...')
        detect_patterns_for_all_users()
        self.stdout.write(self.style.SUCCESS('Pattern detection complete'))
```

**Run migrations:**
```bash
python manage.py makemigrations
python manage.py migrate
```

**Test pattern detection manually:**
```bash
python manage.py run_pattern_detection
```

**Set up automatic daily runs using Django-Q:**

Start the Django-Q cluster in a separate terminal:
```bash
python manage.py qcluster
```

Then schedule the task (run this in Django shell: `python manage.py shell`):
```python
from django_q.models import Schedule
from django_q.tasks import schedule

# Schedule daily at 10 AM
schedule(
    'notifications.tasks.detect_patterns_for_all_users',
    schedule_type=Schedule.DAILY,
    name='Daily pattern detection',
    repeats=-1  # Repeat indefinitely
)
```

**Create Serializers for Notifications (backend/notifications/serializers.py):**
```python
from rest_framework import serializers
from .models import ProactivePrompt, HelpRequest

class ProactivePromptSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProactivePrompt
        fields = '__all__'
        read_only_fields = ('id', 'user', 'created_at')

class HelpRequestSerializer(serializers.ModelSerializer):
    supporter_name = serializers.CharField(source='supporter.supporter_name', read_only=True)
    
    class Meta:
        model = HelpRequest
        fields = '__all__'
        read_only_fields = ('id', 'user', 'sent_at')
```

**Create Views for Notifications (backend/notifications/views.py):**
```python
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.core.mail import send_mail
from django.conf import settings
from .models import ProactivePrompt, HelpRequest
from .serializers import ProactivePromptSerializer, HelpRequestSerializer
from support.models import SupportPerson

class ProactivePromptViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProactivePromptSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return ProactivePrompt.objects.filter(user=self.request.user)
    
    @action(detail=True, methods=['post'])
    def dismiss(self, request, pk=None):
        prompt = self.get_object()
        prompt.dismissed = True
        prompt.dismissed_at = timezone.now()
        prompt.save()
        return Response({'status': 'dismissed'})

class HelpRequestViewSet(viewsets.ModelViewSet):
    serializer_class = HelpRequestSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return HelpRequest.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        help_request = serializer.save(user=self.request.user)
        
        # Send email notification
        supporter = help_request.supporter
        user = self.request.user
        
        subject = f"{user.first_name} is asking for support"
        message = f"""Hi {supporter.supporter_name},

{user.first_name} wanted to reach out to you.

Message: {help_request.message_text}

They're going through a tough time right now. A check-in or some company would mean a lot.

💙 Mental Health Bridge
        """
        
        if supporter.supporter_email:
            try:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [supporter.supporter_email],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Error sending email: {e}")
```

**Create URLs for Notifications (backend/notifications/urls.py):**
```python
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'proactive-prompts', views.ProactivePromptViewSet, basename='proactive-prompt')
router.register(r'help-requests', views.HelpRequestViewSet, basename='help-request')

urlpatterns = [
    path('', include(router.urls)),
]
```

**Update main URLs (backend/config/urls.py):**
```python
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),
    path('api/', include('checkins.urls')),
    path('api/', include('support.urls')),
    path('api/', include('notifications.urls')),
]
```

### Week 5: History View & Help Requests

**Frontend: History Page (frontend/src/pages/History.js):**
```javascript
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { format } from 'date-fns';
import { ThumbsUp, Meh, ThumbsDown } from 'lucide-react';

function History() {
  const [checkins, setCheckins] = useState([]);