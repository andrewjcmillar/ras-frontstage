import logging

from flask import redirect, render_template, request, url_for, abort
from structlog import wrap_logger

from frontstage.controllers import party_controller
from frontstage.exceptions.exceptions import ApiError
from frontstage.models import ResetPasswordForm
from frontstage.views.passwords import passwords_bp


logger = wrap_logger(logging.getLogger(__name__))


@passwords_bp.route('/reset-password/<token>', methods=['GET'])
def get_reset_password(token, form_errors=None):
    form = ResetPasswordForm(request.form)

    try:
        party_controller.verify_token(token)
    except ApiError as exc:
        if exc.status_code == 409:
            logger.warning('Token expired', api_url=exc.url, api_status_code=exc.status_code, token=token)
            return render_template('passwords/password-expired.html', token=token)
        elif exc.status_code == 404:
            logger.warning('Invalid token sent to party service', api_url=exc.url, api_status_code=exc.status_code,
                           token=token)
            abort(404)
        else:
            raise exc

    template_data = {
        "error": {
            "type": form_errors
        },
        'token': token
    }
    return render_template('passwords/reset-password.html', form=form, data=template_data)


@passwords_bp.route('/reset-password/<token>', methods=['POST'])
def post_reset_password(token):
    form = ResetPasswordForm(request.form)

    if not form.validate():
        return get_reset_password(token, form_errors=form.errors)

    password = request.form.get('password')

    try:
        party_controller.change_password(password, token)
    except ApiError as exc:
        if exc.status_code == 409:
            logger.warning('Token expired', api_url=exc.url, api_status_code=exc.status_code, token=token)
            return render_template('passwords/password-expired.html', token=token)
        elif exc.status_code == 404:
            logger.warning('Invalid token sent to party service', api_url=exc.url, api_status_code=exc.status_code,
                           token=token)
            abort(404)
        else:
            raise exc

    logger.info('Successfully changed user password', token=token)
    return redirect(url_for('passwords_bp.reset_password_confirmation'))


@passwords_bp.route('/reset-password/confirmation', methods=['GET'])
def reset_password_confirmation():
    return render_template('passwords/reset-password.confirmation.html')


@passwords_bp.route('/resend-password-email-expired-token/<token>', methods=['GET'])
def resend_password_email_expired_token(token):
    party_controller.resend_password_email_expired_token(token)
    logger.info('Re-sent password email for expired token.', token=token)
    return redirect(url_for('passwords_bp.reset_password_check_email'))


@passwords_bp.route('/reset-password/check-email', methods=['GET'])
def reset_password_check_email():
    return render_template('passwords/reset-password.check-email.html')
