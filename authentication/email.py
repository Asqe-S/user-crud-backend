from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.conf import settings


def send_verification_email(subject, uid, token, valid_until,  username, email, otp=None):

    emailcontext = {
        'subject': subject,
        'valid_until': valid_until,
        'otp': otp,
        'username': username,
        'uid': uid,
        'token': token,
        'domain': settings.DOMAIN[0]

    }
    message = render_to_string('email.html', emailcontext)
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email,]

    email = EmailMessage(subject, message, from_email, recipient_list)
    email.content_subtype = 'html'
    email.send()
