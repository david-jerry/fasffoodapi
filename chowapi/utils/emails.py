from typing import Optional
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils.encoding import force_str

from .request_context import request_context as context_manager  # Ensure you have the correct import path


class CustomEmailSender:
    """
    Example use:

    def send_email_view(request):
        # Instantiate YourEmailSender
        email_sender = YourEmailSender()

        # Define dynamic content for the email templates
        context = {
            'username': 'John Doe',
            'confirmation_link': 'https://example.com/confirm/',
        }

        # Set the template prefix (assuming you have templates named
        # "your_template_subject.txt",
        # "your_template_message.html",
        # "your_template_message.txt")

        template_prefix = "your_template"

        # Specify the recipient email address or a list of addresses
        recipient_email = 'john.doe@example.com'

        # Send the email
        email_sender.send_mail(template_prefix, recipient_email, context)

    """

    def format_email_subject(self, subject: str):
        """
        Format the email subject with a prefix from settings or the site name.

        Args:
        - subject (str): The original email subject.

        Returns:
        - str: The formatted email subject.
        """
        prefix = getattr(settings, "EMAIL_SUBJECT_PREFIX", None)
        if prefix is None:
            site = get_current_site(context_manager.request)
            prefix = f"[{site.name}] "
        return prefix + force_str(subject)

    def get_from_email(self):
        """
        Get the 'from' email address for sending emails.

        Returns:
        - str: The 'from' email address.
        """
        return getattr(settings, "DEFAULT_FROM_EMAIL", None)

    def render_mail(self, template_prefix: str, email: str, context: Optional[dict], headers=None):
        """
        Render an email with HTML and plain text alternatives.

        Args:
        - template_prefix (str): The prefix of the email template.
        - email (str or list): The recipient email address or a list of addresses.
        - context (dict): The context to render the email templates.
        - headers (dict): Additional headers for the email.

        Returns:
        - EmailMultiAlternatives or EmailMessage: The rendered email message.
        """
        to = [email] if isinstance(email, str) else email
        subject_template_name = f"{template_prefix}_subject.txt"
        subject = render_to_string(subject_template_name, context).strip()
        subject = self.format_email_subject(subject)

        from_email = self.get_from_email()

        bodies = {}
        for ext in ["html", "txt"]:
            try:
                template_name = f"{template_prefix}_message.{ext}"
                bodies[ext] = render_to_string(template_name, context).strip()
            except TemplateDoesNotExist:
                if ext == "txt" and not bodies:
                    raise  # We need at least one body

        if "txt" in bodies:
            msg = EmailMultiAlternatives(subject, bodies["txt"], from_email, to, headers=headers)
            if "html" in bodies:
                msg.attach_alternative(bodies["html"], "text/html")
        else:
            msg = EmailMessage(subject, bodies["html"], from_email, to, headers=headers)
            msg.content_subtype = "html"  # Main content is now text/html

        return msg

    def send_mail(self, template_prefix: str, email: str, context: Optional[dict]):
        """
        Send an email using the specified template prefix and context.

        Args:
        - template_prefix (str): The prefix of the email template.
        - email (str or list): The recipient email address or a list of addresses.
        - context (dict): The context to render the email templates.

        Returns:
        - None
        """
        msg = self.render_mail(template_prefix, email, context)
        msg.send()
