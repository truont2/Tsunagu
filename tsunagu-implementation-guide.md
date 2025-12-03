# Tsunagu - Technical Build Guide
## React Native + Django Implementation

---

## Core Architecture

**Stack:**
- **Mobile:** React Native + Expo (managed workflow)
- **Backend:** Django REST Framework + PostgreSQL
- **Queue:** Django-Q with Redis
- **Push:** Expo Push Notifications
- **Auth:** JWT + Expo SecureStore + Biometrics

---

## Database Schema (Copy-Paste Ready)

```python
# models.py

from django.db import models
from django.contrib.auth.models import AbstractUser
import secrets

class User(AbstractUser):
    ROLE_CHOICES = [
        ('user', 'Person with Depression'),
        ('supporter', 'Support Network Member'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    onboarded = models.BooleanField(default=False)
    biometric_enabled = models.BooleanField(default=False)
    push_token = models.CharField(max_length=200, blank=True)
    timezone = models.CharField(max_length=50, default='UTC')
    allow_proactive_prompts = models.BooleanField(default=True)
    prompt_delay_hours = models.IntegerField(default=24)

class MoodCheckIn(models.Model):
    MOOD_CHOICES = [
        ('good', 'Good'),
        ('neutral', 'Neutral'),
        ('bad', 'Bad'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    mood = models.CharField(max_length=10, choices=MOOD_CHOICES)
    created_via = models.CharField(max_length=10, default='app')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'date'],
                name='one_checkin_per_day'
            )
        ]

class SupportRelationship(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='supported_by')
    supporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='supporting')
    invite_code = models.CharField(
        max_length=6,
        unique=True,
        default=lambda: secrets.token_urlsafe(4)[:6].upper()
    )
    status = models.CharField(max_length=20, default='pending')
    can_receive_proactive_alerts = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

class AlertQueue(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    pattern_type = models.CharField(max_length=20)  # consecutive_bad, no_checkin
    pattern_data = models.JSONField()
    severity = models.CharField(max_length=10)
    detected_at = models.DateTimeField(auto_now_add=True)
    user_notified_at = models.DateTimeField(null=True)
    response_deadline = models.DateTimeField()
    user_response = models.CharField(max_length=20, default='pending')
    supporters_notified_at = models.DateTimeField(null=True)

class HelpRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    template = models.CharField(max_length=20)
    custom_message = models.TextField(blank=True)
    supporters_notified = models.ManyToManyField(User, related_name='help_requests_received')
    sent_at = models.DateTimeField(auto_now_add=True)
    mood_context = models.JSONField(null=True)
```

---

## Project Setup Commands

### Backend Setup
```bash
# Create Django project
django-admin startproject tsunagu_backend
cd tsunagu_backend
python -m venv venv
source venv/bin/activate

# Install everything
pip install django djangorestframework djangorestframework-simplejwt
pip install django-cors-headers psycopg2-binary redis django-q2
pip install python-decouple drf-spectacular

# Create app
python manage.py startapp api

# Database
createdb tsunagu_db
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

### Mobile Setup
```bash
# Create Expo app
npx create-expo-app tsunagu --template blank-typescript
cd tsunagu

# Core dependencies
npx expo install expo-notifications expo-secure-store expo-local-authentication
npx expo install @react-navigation/native @react-navigation/stack @react-navigation/bottom-tabs
npm install zustand axios date-fns
npx expo install react-native-safe-area-context react-native-screens

# UI (using NativeWind for Tailwind in RN)
npm install nativewind
npm install --dev tailwindcss
npx tailwindcss init
```

---

## Django Settings Configuration

```python
# settings.py

from pathlib import Path
from datetime import timedelta
from decouple import config

SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_q',
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', default='http://localhost:19006').split(',')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME', default='tsunagu_db'),
        'USER': config('DB_USER', default='postgres'),
        'PASSWORD': config('DB_PASSWORD', default=''),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
    }
}

AUTH_USER_MODEL = 'api.User'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
}

Q_CLUSTER = {
    'name': 'tsunagu',
    'workers': 4,
    'recycle': 500,
    'timeout': 60,
    'compress': True,
    'save_limit': 250,
    'queue_limit': 500,
    'cpu_affinity': 1,
    'label': 'Django Q',
    'redis': {
        'host': config('REDIS_HOST', default='localhost'),
        'port': 6379,
        'db': 0,
    }
}
```

---

## API Endpoints Implementation

```python
# api/views.py

from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from datetime import datetime, timedelta
from .models import *
from .serializers import *

@api_view(['POST'])
def register(request):
    """Register user or supporter based on role"""
    role = request.data.get('role')
    if role not in ['user', 'supporter']:
        return Response({'error': 'Invalid role'}, status=400)
    
    user = User.objects.create_user(
        username=request.data.get('email'),
        email=request.data.get('email'),
        password=request.data.get('password'),
        role=role,
        first_name=request.data.get('first_name', '')
    )
    
    if role == 'supporter':
        # Supporter needs invite code
        invite_code = request.data.get('invite_code')
        if invite_code:
            # Auto-create relationship
            pass
    
    # Return tokens
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(user)
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'user': {'id': user.id, 'role': user.role}
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mood_checkin(request):
    """Create daily mood check-in"""
    today = timezone.now().date()
    
    # Check if already exists (will fail at DB level too)
    if MoodCheckIn.objects.filter(user=request.user, date=today).exists():
        return Response({'error': 'Already checked in today'}, status=400)
    
    checkin = MoodCheckIn.objects.create(
        user=request.user,
        date=today,
        mood=request.data.get('mood'),
        created_via=request.data.get('created_via', 'app')
    )
    
    # Trigger pattern detection
    from django_q.tasks import async_task
    async_task('api.tasks.check_patterns', request.user.id)
    
    return Response({'id': checkin.id, 'mood': checkin.mood})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_today_checkin(request):
    """Check if user already checked in today"""
    today = timezone.now().date()
    checkin = MoodCheckIn.objects.filter(user=request.user, date=today).first()
    
    if checkin:
        return Response({'checked_in': True, 'mood': checkin.mood})
    return Response({'checked_in': False})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_invite_code(request):
    """Generate invite code for supporter"""
    if request.user.role != 'user':
        return Response({'error': 'Only users can invite supporters'}, status=403)
    
    # Create pending relationship with code
    code = secrets.token_urlsafe(4)[:6].upper()
    # Store this code somewhere
    
    return Response({'invite_code': code})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def respond_to_alert(request, alert_id):
    """User responds to safety valve notification"""
    alert = AlertQueue.objects.get(id=alert_id, user=request.user)
    
    if alert.user_response != 'pending':
        return Response({'error': 'Already responded'}, status=400)
    
    response = request.data.get('response')  # 'approved' or 'cancelled'
    alert.user_response = response
    alert.save()
    
    if response == 'approved':
        # Notify supporters
        from django_q.tasks import async_task
        async_task('api.tasks.notify_supporters', alert.id)
    
    return Response({'status': 'success'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_help_request(request):
    """Send help request to supporters"""
    template = request.data.get('template')
    
    help_request = HelpRequest.objects.create(
        user=request.user,
        template=template,
        custom_message=request.data.get('custom_message', '')
    )
    
    # Get active supporters
    supporters = User.objects.filter(
        supporting__user=request.user,
        supporting__status='active'
    )
    
    help_request.supporters_notified.set(supporters)
    
    # Send notifications
    from django_q.tasks import async_task
    async_task('api.tasks.send_help_notifications', help_request.id)
    
    return Response({'status': 'sent', 'supporters_count': supporters.count()})
```

---

## Background Tasks

```python
# api/tasks.py

from django.utils import timezone
from datetime import timedelta
from .models import *
from .notifications import send_push_notification

def check_patterns(user_id):
    """Check for patterns that need alerts"""
    user = User.objects.get(id=user_id)
    
    # Get last 7 days of check-ins
    recent = MoodCheckIn.objects.filter(
        user=user,
        date__gte=timezone.now().date() - timedelta(days=7)
    ).order_by('-date')
    
    # Check consecutive bad days
    consecutive_bad = 0
    for checkin in recent:
        if checkin.mood == 'bad':
            consecutive_bad += 1
        else:
            break
    
    if consecutive_bad >= 3:
        # Check if we already alerted recently
        recent_alert = AlertQueue.objects.filter(
            user=user,
            pattern_type='consecutive_bad',
            detected_at__gte=timezone.now() - timedelta(days=3)
        ).exists()
        
        if not recent_alert:
            alert = AlertQueue.objects.create(
                user=user,
                pattern_type='consecutive_bad',
                pattern_data={'days': consecutive_bad},
                severity='medium' if consecutive_bad == 3 else 'high',
                response_deadline=timezone.now() + timedelta(hours=24)
            )
            
            # Send push to user (safety valve)
            send_push_notification(
                user.push_token,
                title="Check-in on your wellbeing",
                body=f"You've had {consecutive_bad} difficult days. Should we let your support network know?",
                data={'type': 'safety_valve', 'alert_id': alert.id}
            )
            
            alert.user_notified_at = timezone.now()
            alert.save()

def notify_supporters(alert_id):
    """Send notifications to supporters after user approves"""
    alert = AlertQueue.objects.get(id=alert_id)
    
    supporters = User.objects.filter(
        supporting__user=alert.user,
        supporting__status='active',
        supporting__can_receive_proactive_alerts=True
    )
    
    for supporter in supporters:
        send_push_notification(
            supporter.push_token,
            title=f"{alert.user.first_name} needs support",
            body=f"They've been struggling for {alert.pattern_data['days']} days",
            data={'type': 'support_alert', 'user_id': alert.user.id}
        )
    
    alert.supporters_notified_at = timezone.now()
    alert.save()

def process_expired_alerts():
    """Handle alerts where user didn't respond"""
    expired = AlertQueue.objects.filter(
        user_response='pending',
        response_deadline__lt=timezone.now()
    )
    
    for alert in expired:
        alert.user_response = 'expired'
        alert.save()
        # Don't notify supporters - safe default

# Schedule this to run every evening
def daily_pattern_check():
    """Run pattern detection for all users"""
    users = User.objects.filter(role='user', allow_proactive_prompts=True)
    for user in users:
        check_patterns(user.id)
```

---

## React Native Implementation

### API Service
```typescript
// services/api.ts
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

const API_URL = process.env.EXPO_PUBLIC_API_URL || 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_URL,
  timeout: 10000,
});

// Add token to requests
api.interceptors.request.use(async (config) => {
  const token = await SecureStore.getItemAsync('accessToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const refreshToken = await SecureStore.getItemAsync('refreshToken');
      if (refreshToken) {
        try {
          const { data } = await axios.post(`${API_URL}/auth/refresh/`, {
            refresh: refreshToken,
          });
          await SecureStore.setItemAsync('accessToken', data.access);
          error.config.headers.Authorization = `Bearer ${data.access}`;
          return api.request(error.config);
        } catch {
          // Navigate to login
        }
      }
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (data: any) => api.post('/auth/register/', data),
  login: (data: any) => api.post('/auth/login/', data),
};

export const checkInAPI = {
  create: (mood: string) => api.post('/checkins/', { mood }),
  getToday: () => api.get('/checkins/today/'),
};

export const supportAPI = {
  generateInvite: () => api.post('/support/invite/'),
  joinWithCode: (code: string) => api.post('/support/join/', { code }),
};

export const alertAPI = {
  respond: (alertId: number, response: string) => 
    api.post(`/alerts/${alertId}/respond/`, { response }),
};
```

### State Management
```typescript
// stores/useStore.ts
import { create } from 'zustand';

interface AppState {
  user: any;
  todayCheckIn: any;
  isAuthenticated: boolean;
  
  setUser: (user: any) => void;
  setTodayCheckIn: (checkIn: any) => void;
  logout: () => void;
}

export const useStore = create<AppState>((set) => ({
  user: null,
  todayCheckIn: null,
  isAuthenticated: false,
  
  setUser: (user) => set({ user, isAuthenticated: true }),
  setTodayCheckIn: (checkIn) => set({ todayCheckIn: checkIn }),
  logout: () => set({ user: null, isAuthenticated: false, todayCheckIn: null }),
}));
```

### Main Check-In Screen
```tsx
// screens/CheckInScreen.tsx
import React, { useState, useEffect } from 'react';
import { View, Text, TouchableOpacity, Alert } from 'react-native';
import { checkInAPI } from '../services/api';
import { useStore } from '../stores/useStore';

export const CheckInScreen = () => {
  const [loading, setLoading] = useState(false);
  const { todayCheckIn, setTodayCheckIn } = useStore();

  useEffect(() => {
    checkTodayStatus();
  }, []);

  const checkTodayStatus = async () => {
    try {
      const { data } = await checkInAPI.getToday();
      if (data.checked_in) {
        setTodayCheckIn(data);
      }
    } catch (error) {
      console.error(error);
    }
  };

  const handleCheckIn = async (mood: string) => {
    if (todayCheckIn) {
      Alert.alert('Already checked in today!');
      return;
    }

    setLoading(true);
    try {
      const { data } = await checkInAPI.create(mood);
      setTodayCheckIn(data);
      Alert.alert('Check-in saved!');
    } catch (error) {
      Alert.alert('Error', 'Failed to save check-in');
    }
    setLoading(false);
  };

  if (todayCheckIn) {
    return (
      <View className="flex-1 justify-center items-center p-4">
        <Text className="text-2xl mb-4">Already checked in today ✓</Text>
        <Text className="text-lg">You selected: {todayCheckIn.mood}</Text>
      </View>
    );
  }

  return (
    <View className="flex-1 justify-center items-center p-4">
      <Text className="text-2xl mb-8">How are you feeling today?</Text>
      
      <View className="flex-row gap-4">
        <TouchableOpacity 
          onPress={() => handleCheckIn('good')}
          disabled={loading}
          className="p-8 bg-green-500 rounded-xl"
        >
          <Text className="text-4xl">😊</Text>
          <Text className="text-white mt-2">Good</Text>
        </TouchableOpacity>

        <TouchableOpacity 
          onPress={() => handleCheckIn('neutral')}
          disabled={loading}
          className="p-8 bg-yellow-500 rounded-xl"
        >
          <Text className="text-4xl">😐</Text>
          <Text className="text-white mt-2">Neutral</Text>
        </TouchableOpacity>

        <TouchableOpacity 
          onPress={() => handleCheckIn('bad')}
          disabled={loading}
          className="p-8 bg-red-500 rounded-xl"
        >
          <Text className="text-4xl">😔</Text>
          <Text className="text-white mt-2">Bad</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
};
```

### Push Notifications Setup
```typescript
// utils/notifications.ts
import * as Notifications from 'expo-notifications';
import { Platform } from 'react-native';

export const registerForPushNotifications = async () => {
  const { status } = await Notifications.requestPermissionsAsync();
  if (status !== 'granted') return null;
  
  const token = await Notifications.getExpoPushTokenAsync();
  
  // Set up notification categories for inline actions
  if (Platform.OS === 'ios') {
    await Notifications.setNotificationCategoryAsync('MOOD_CHECKIN', [
      { identifier: 'good', buttonTitle: '😊 Good' },
      { identifier: 'neutral', buttonTitle: '😐 Neutral' },
      { identifier: 'bad', buttonTitle: '😔 Bad' },
    ]);
    
    await Notifications.setNotificationCategoryAsync('SAFETY_VALVE', [
      { identifier: 'approve', buttonTitle: 'Yes, notify them' },
      { identifier: 'cancel', buttonTitle: "I'm okay" },
    ]);
  }
  
  return token.data;
};

// Handle background responses
Notifications.setNotificationResponseReceivedListener(response => {
  const { actionIdentifier, notification } = response;
  
  if (notification.request.content.data?.type === 'MOOD_CHECKIN') {
    // Save mood check-in
    checkInAPI.create(actionIdentifier);
  } else if (notification.request.content.data?.type === 'safety_valve') {
    // Respond to safety valve
    const alertId = notification.request.content.data.alert_id;
    alertAPI.respond(alertId, actionIdentifier === 'approve' ? 'approved' : 'cancelled');
  }
});
```

---

## MVP Features Priority

### Week 1: Core Foundation
1. User registration (role selection)
2. JWT auth with biometric/persistent login
3. Basic mood check-in
4. Push notification setup

### Week 2: Support Network
1. Invite code generation
2. Supporter joins with code
3. Support relationship creation
4. Basic supporter dashboard

### Week 3: Safety Systems
1. Pattern detection (3 consecutive bad days)
2. Safety valve notifications to user
3. User approval/cancel flow
4. Supporter notifications after approval

### Week 4: Polish
1. Help request templates
2. Offline queue for check-ins
3. Error handling
4. Deploy to TestFlight/Play Store

---

## Deployment

### Environment Variables
```bash
# .env for Django
SECRET_KEY=generate-a-long-random-string
DEBUG=False
DATABASE_URL=postgresql://user:pass@localhost/tsunagu
REDIS_URL=redis://localhost:6379
ALLOWED_HOSTS=api.tsunagu.app
CORS_ALLOWED_ORIGINS=https://tsunagu.app

# .env for React Native
EXPO_PUBLIC_API_URL=https://api.tsunagu.app/api
```

### Quick Deploy Commands
```bash
# Backend (Railway)
railway init
railway add
railway up

# Mobile (EAS Build)
eas build --platform ios --profile preview
eas build --platform android --profile preview
eas submit -p ios
eas submit -p android
```

---

## Testing the Core Flow

1. **User signs up** → Role: user
2. **Enable notifications** → Get push token
3. **First check-in** → Mood: bad
4. **Day 2-3** → More bad moods
5. **Pattern detected** → Safety valve push sent
6. **User approves** → Supporters notified
7. **Supporter opens app** → Sees alert, takes action

---

## Common Issues & Fixes

### Push Notifications Not Working
- iOS: Must test on real device, not simulator
- Android: Check Google Play Services
- Both: Ensure push token is saved to backend

### Check-in Duplicate Error
- Database constraint is working correctly
- Check timezone handling - might be date mismatch

### Biometric Auth Failing
- Not available on simulator
- User must have biometrics set up on device
- Fallback to PIN/password

### Pattern Detection Not Running
- Check Django-Q is running: `python manage.py qcluster`
- Check Redis connection
- Verify scheduled task is created

---

That's it. Everything you need to build the MVP. Focus on getting the core loop working first: check-in → pattern detection → safety valve → supporter notification.