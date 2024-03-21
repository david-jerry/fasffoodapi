from allauth.account.signals import user_logged_in, user_signed_up, user_logged_out

from django.contrib.auth.signals import user_logged_in as admin_logged_in
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.utils.timezone import datetime as now
from django.core.cache import cache

from chowapi.users.models import Activities, User, UserSessions, RiderParticulars
from chowapi.utils.logger import LOGGER

today = now.today()

@receiver(post_save, sender=User)
def create_user_relationship(sender, instance, created, **kwargs):
    if created:
        if instance.is_rider:
            RiderParticulars.objects.create(user=instance)
        LOGGER.info(
            """
USER RELATIONSHIPS CREATED
--------------------------
PROFILE - Created
RIDER   - Created
            """
        )

        user_dict = {
            "id": instance.id,
            "unique_id": instance.unique_id,
            "email": instance.email,
            "phone": instance.phone,
            "name": instance.name,
            "country": instance.country,
            "ip_address": instance.ip_address,
            "currency": instance.currency,
            "is_active": instance.is_active,
            "is_staff": instance.is_staff,
            "is_vendor": instance.is_vendor,
            "is_customer": instance.is_customer,
            "is_rider": instance.is_rider,
            "date_joined": instance.date_joined,
        }

        if not instance.is_staff:
            Activities.objects.create(identity=instance.name, activity_type=Activities.SIGNUP)
        cached_users = cache.get("users", [])
        cached_users.append(user_dict)
        cache.set("users", cached_users)

    if not created and settings.FORCE_END_INACTIVE_USER_SESSIONS:
        if not instance.is_active:
            qs = UserSessions.objects.filter(user=instance)
            for i in qs:
                i.end_session()

@receiver(user_signed_up)
def perform_actions_on_signup(sender, request, user, **kwargs):
    if request.user.is_staff:
        Activities.objects.create(identity=user.phone, country=request.country_code, activity_type=Activities.LOGIN)

    user.country = request.country_code
    user.ip_address = request.ip
    user.currency = request.currency_native_short
    
    user.save(update_fields=[
        "country",
        "ip_address",
        "currency",
    ])

@receiver(admin_logged_in)
def admin_actions_on_login(sender, request, user, **kwargs):
    LOGGER.info("logged in triggered")
    if request.user.is_staff:
        Activities.objects.create(identity=user.phone, country=request.country_code, activity_type=Activities.LOGIN)

    if not user.country or not user.ip_address or not user.currency:
        user.country = request.country_code
        user.ip_address = request.ip
        user.currency = request.currency_native_short
        user.save(update_fields=[
            "country",
            "ip_address",
            "currency",
        ])

    session_key = request.session.session_key
    LOGGER.debug(f"Session Key: {session_key}")
    if session_key and user.is_active and settings.FORCE_USER_SESSIONS_TO_ONE:
        UserSessions.objects.update_or_create(user=user, ip_address=request.ip, defaults={
            "user":user,
            "session_key":session_key,
            "ip_address":request.ip,
            "country_code":request.country_code,
            "continent_code":request.continent_code,
            "region":request.region,
            "country_flag":request.country_flag,
            "uses_vpn":request.uses_vpn,
            "active":True,
            "ended":False,
        })

        LOGGER.info(
            """
USER SESSION CREATED
--------------------------
An active user session has been created successfully
            """
        )


@receiver(user_logged_in)
def perform_actions_on_login(sender, request, user, **kwargs):
    LOGGER.info("logged in triggered")
    if request.user.is_staff:
        Activities.objects.create(identity=user.phone, country=request.country_code, activity_type=Activities.LOGIN)

    if not user.country or not user.ip_address or not user.currency:
        user.country = request.country_code
        user.ip_address = request.ip
        user.currency = request.currency_native_short
        user.save(update_fields=[
            "country",
            "ip_address",
            "currency",
        ])

    session_key = request.session.session_key
    LOGGER.debug(f"Session Key: {session_key}")
    if session_key and user.is_active and settings.FORCE_USER_SESSIONS_TO_ONE:
        UserSessions.objects.update_or_create(user=user, ip_address=request.ip, defaults={
            "user":user,
            "session_key":session_key,
            "ip_address":request.ip,
            "country_code":request.country_code,
            "continent_code":request.continent_code,
            "region":request.region,
            "country_flag":request.country_flag,
            "uses_vpn":request.uses_vpn,
            "active":True,
            "ended":False,
        })

        LOGGER.info(
            """
USER SESSION CREATED
--------------------------
An active user session has been created successfully
            """
        )

@receiver(user_logged_out)
def perform_actions_on_logout(sender, request, user, **kwargs):
    qs = UserSessions.objects.filter(user=user)
    for i in qs:
        i.end_session()

        LOGGER.info(
            f"""
USER SESSION ENDED
--------------------------
{user.name.title()} session has been terminated successfully
            """
        )



@receiver(post_save, sender=UserSessions)
def end_sessions(sender, instance, created, *args, **kwargs):
    if created:
        qs = UserSessions.objects.filter(user=instance.user,  ended=False, active=False).exclude(id=instance.id)
        for i in qs:
            i.end_session()

        LOGGER.info(
            """
USER SESSION ENDED
--------------------------
An active user session has been terminated successfully
            """
        )
    if not instance.active and not instance.ended:
        instance.end_session()

        LOGGER.info(
            """
USER SESSION ENDED
--------------------------
An active user session has been terminated successfully
            """
        )

