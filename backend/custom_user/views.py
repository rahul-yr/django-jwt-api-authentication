from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from .serializers import UserTokenSerializer
from .models import CustomUser,UserToken
from rest_framework import views, mixins, permissions, exceptions, status
from rest_framework.utils import json
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.settings import api_settings
from django.utils import timezone
import requests
from rest_framework.permissions import IsAuthenticated,IsAdminUser



def login_user_provider(request):
    error = {'error': 'wrong token / this token is already expired.'}

    if request.data["provider"] == 'google':
        payload = {'access_token': request.data["token"]}
        r = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', params=payload)
        data = json.loads(r.text)

        if 'error' in data:
            return error

        return data
    else:
        # Add other providers if necessary
        return error




@api_view(['POST'])
def login_user(request):
    '''
    This is a method to create user or login existing user using social auth
    '''
    try:
        if "token" in request.data and "provider" in request.data:
            data = login_user_provider(request)
            # Check the token is valid or not
            if 'error' in data:
                return Response(data)

            # Extract all required Parameters
            email = data['email']

            try:
                user = CustomUser.objects.get(email=email)
                # Check user account is active or not
                if not user.is_active:
                    return Response(data={'error':'Account disabled'},status=status.HTTP_403_FORBIDDEN)
                
                # User Token Validation
                user_token = UserToken.objects.get(user=user)
                
                # retrive valid token details if present for the user
                current_time = timezone.now()
                refresh_token_last_updated = user_token.refresh_token_updated
                diff_refresh_token = current_time-refresh_token_last_updated
                
                access_token_last_updated = user_token.access_token_updated
                diff_access_token = current_time-access_token_last_updated

                # If refresh token is not updated in last 24 hours create a new token pair
                if int(diff_refresh_token.total_seconds()) >= 82800:
                    print('Generate Tokens and save model')

                    correct = False
                    token = RefreshToken.for_user(user) 
                    while correct==False:
                        if not UserToken.objects.filter(refresh_token=str(token)).exists() and not UserToken.objects.filter(access_token=str(token.access_token)).exists():
                            correct=True
                        else:
                            token = RefreshToken.for_user(user) 
                
                    user_token.access_token=str(token.access_token)
                    user_token.refresh_token=str(token)
                    user_token.access_token_updated=timezone.now()
                    user_token.refresh_token_updated=timezone.now()
                    user_token.save()

                    serializer = UserTokenSerializer(user_token)
                    return Response(serializer.data)

                else:
                    # access token is invalid if it's more than 4 minutes back last generated
                    if int(diff_access_token.total_seconds()) >= 240:
                        # refresh access token alone, save and return
                        print('refresh access token only')

                        # -----------------------Token Part starts

                        input = {}
                        input['refresh']=user_token.refresh_token
                        # ---------------------------------------

                        refresh = RefreshToken(input['refresh'])
                        correct = False
                        while correct==False:
                            if not UserToken.objects.filter(access_token=str(refresh.access_token)).exists():
                                correct=True
                            else:
                                refresh = RefreshToken(input['refresh'])

                        data = {'access': str(refresh.access_token)}

                        # if api_settings.ROTATE_REFRESH_TOKENS:
                        #     if api_settings.BLACKLIST_AFTER_ROTATION:
                        #         try:
                        #             # Attempt to blacklist the given refresh token
                        #             refresh.blacklist()
                        #         except AttributeError:
                        #             # If blacklist app not installed, `blacklist` method will
                        #             # not be present
                        #             pass

                        #     refresh.set_jti()
                        #     refresh.set_exp()

                        #     data['refresh'] = str(refresh)

                        # print(data['access'])
                        
                        # -----------------------Token Part ends
                        user_token.access_token=str(data['access'])
                        user_token.access_token_updated=timezone.now()
                        user_token.save()
                        serializer = UserTokenSerializer(user_token)
                        return Response(serializer.data)
                    # Return the existing tokens
                    else:
                        # if token is valid retrieve and return that token itself
                        print('return existing tokens')
                        serializer = UserTokenSerializer(user_token)
                        return Response(serializer.data)
            # If user doesn't exist create a new user
            except CustomUser.DoesNotExist:
                # Create and save user if not exists
                user = CustomUser.objects.create_user(email=email,is_active=True)
                user.save()
                # Generate Authorization Tokens

                token = RefreshToken.for_user(user) 
                correct=False

                while correct==False:
                    if not UserToken.objects.filter(refresh_token=str(token)).exists() and not UserToken.objects.filter(access_token=str(token.access_token)).exists():
                        correct=True
                    else:
                        token = RefreshToken.for_user(user) 

                # Create an access token and save
                user_token = UserToken.objects.create(user=user,\
                                                    access_token=str(token.access_token),\
                                                    refresh_token=str(token),\
                                                    access_token_updated=timezone.now(),\
                                                    refresh_token_updated=timezone.now())
                user_token.save()

                serializer = UserTokenSerializer(user_token)
                return Response(serializer.data)

        else:
            return Response(status=status.HTTP_412_PRECONDITION_FAILED)
    except Exception as e:
        print(e)
        return Response(status=status.HTTP_400_BAD_REQUEST)

    
@api_view(['POST'])
def refresh_token(request):
    try:
        if "access_token" in request.data and "refresh_token" in request.data and "email" in request.data:
            input = {}
            input['email']=request.data['email']
            input['access_token']=request.data['access_token']
            input['refresh_token']=request.data['refresh_token']

            # If user exists
            if CustomUser.objects.filter(email=input['email']).exists():
                user = CustomUser.objects.get(email=input['email'])

                # If user is active
                if not user.is_active:
                    return Response(data={'error':'Account disabled'},status=status.HTTP_403_FORBIDDEN)

                # if provided token is valid
                if UserToken.objects.filter(user=user,access_token=str(input['access_token']),refresh_token=str(input['refresh_token'])).exists():
                    # Here comes the logic like validation and creation or login again
                    user_token = UserToken.objects.get(user=user)
                    
                    # retrive valid token details if present for the user
                    current_time = timezone.now()
                    refresh_token_last_updated = user_token.refresh_token_updated
                    diff_refresh_token = current_time-refresh_token_last_updated
                    
                    access_token_last_updated = user_token.access_token_updated
                    diff_access_token = current_time-access_token_last_updated

                    # If Refresh Tokens are created in last 24 hours
                    if int(diff_refresh_token.total_seconds()) < 82800:
                        # If access token is created in last 4 minutes
                        if int(diff_access_token.total_seconds()) < 240:
                            serializer = UserTokenSerializer(user_token)
                            return Response(data=serializer.data,status=status.HTTP_200_OK) 
                        # Create new access token if expired
                        else:
                            # generate new token only and save
                            refresh = RefreshToken(input['refresh_token'])
                            correct = False
                            while correct==False:
                                if not UserToken.objects.filter(access_token=str(refresh.access_token)).exists():
                                    correct=True
                                else:
                                    refresh = RefreshToken(input['refresh'])

                            data = {'access': str(refresh.access_token)}
                            # Store data to Model
                            user_token.access_token=str(data['access'])
                            user_token.access_token_updated=timezone.now()
                            user_token.save()
                            serializer = UserTokenSerializer(user_token)
                            return Response(data=serializer.data,status=status.HTTP_200_OK) 

                    else:
                        return Exception({'error':'Please login again'},status.HTTP_401_UNAUTHORIZED)

            raise Exception({'error':'Invalid details'},status.HTTP_404_NOT_FOUND)

        else:
            raise Exception({'error':'All fields are required'},status.HTTP_412_PRECONDITION_FAILED)
    
    except Exception as error:
        if(len(error.args) == 2):
            return Response(data=error.args[0],status=error.args[1])
        else:
            print(error)
            return Response(data={'error':'Not found'},status=status.HTTP_404_NOT_FOUND)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def simple_user(request):
    '''
    This is a method to get user
    '''
    # print(request.data)
    
    try:
        if "refresh_token" in request.data and "email" in request.data:
            input = {}
            input['email']=request.data['email']
            input['access_token']=str(request.headers['Authorization']).split(" ")[1]
            input['refresh_token']=request.data['refresh_token']
            print(input)


    except Exception:
        pass

    # print(request.headers)

    # print(diff.total_seconds())

    # try:
    #     custom_user = CustomUser.objects.get(id=11)
    #     serializer = ListCustomUserSerializer(custom_user)
    #     return Response(serializer.data)
    # except CustomUser.DoesNotExist:
    #     return Response(status=status.HTTP_404_NOT_FOUND)
    
        # return Response({"message": "Got some data!", "data": request.data})
    return Response({"message": "Access Provided"})


    