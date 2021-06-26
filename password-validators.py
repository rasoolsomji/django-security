import re

from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _


class NumberValidator(object):
  def validate(self, password, user=None):
    if not re.findall('\d', password):
      raise ValidationError(
        _("The password must contain at least 1 digit, 0-9."),
        code='password_no_number',
      )
  def get_help_text(self):
    return _(
      "Your password must contain at least 1 digit, 0-9."
    )


class UppercaseValidator(object):
  def validate(self, password, user=None):
    if not re.findall('[A-Z]', password):
      raise ValidationError(
        _("The password must contain at least 1 uppercase letter, A-Z."),
        code='password_no_upper',
      )

  def get_help_text(self):
    return _(
      "Your password must contain at least 1 uppercase letter, A-Z."
    )


class LowercaseValidator(object):
  def validate(self, password, user=None):
    if not re.findall('[a-z]', password):
      raise ValidationError(
        _("The password must contain at least 1 lowercase letter, a-z."),
        code='password_no_lower',
      )

  def get_help_text(self):
    return _(
      "Your password must contain at least 1 lowercase letter, a-z."
    )


class SpecialCharacterValidator(object):
  def validate(self, password, user=None):
    if not re.findall('[@$!%*#?&]', password):
      raise ValidationError(
        _("The password must contain at least 1 special character, @$!%*#?&."),
        code='password_no_special',
      )

  def get_help_text(self):
    return _(
      "Your password must contain at least 1 special character, @$!%*#?&."
    )
