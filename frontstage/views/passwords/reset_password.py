import logging

from flask import redirect, render_template, request, url_for
from structlog import wrap_logger

from frontstage import app
from frontstage.common.api_call import api_call
from frontstage.exceptions.exceptions import ApiError
from frontstage.models import ResetPasswordForm
from frontstage.views.passwords import passwords_bp


logger = wrap_logger(logging.getLogger(__name__))


@passwords_bp.route('/reset-password/<token>', methods=['GET'])
def get_reset_password(token, form_errors=None):
    form = ResetPasswordForm(request.form)

    url = app.config['VERIFY_PASSWORD_TOKEN']
    parameters = {"token": token}
    response = api_call('GET', url, parameters=parameters)

    if response.status_code == 409:
        logger.warning('Token expired', token=token)
        return render_template('passwords/password-expired.html', _theme='default')
    elif response.status_code == 404:
        logger.warning('Invalid token sent to party service', token=token)
        return redirect(url_for('error_bp.not_found_error_page'))
    elif response.status_code != 200:
        logger.error('Party service failed to verify token')
        raise ApiError(response)

    template_data = {
        "error": {
            "type": form_errors
        },
        'token': token
    }
    return render_template('passwords/reset-password.html', _theme='default',
                           form=form, data=template_data)


@passwords_bp.route('/reset-password/<token>', methods=['POST'])
def post_reset_password(token):
    form = ResetPasswordForm(request.form)

    if not form.validate():
        return get_reset_password(token, form_errors=form.errors)

    password = request.form.get('password')
    put_data = {
        "new_password": password,
        "token": token
    }

    url = app.config['CHANGE_PASSWORD']
    response = api_call('PUT', url, json=put_data)

    if response.status_code == 409:
        logger.warning('Token expired', token=token)
        return render_template('passwords/password-expired.html', _theme='default')
    elif response.status_code == 404:
        logger.warning('Invalid token sent to party service', token=token)
        return redirect(url_for('error_bp.not_found_error_page'))
    elif response.status_code != 200:
        logger.error('Party service failed to verify token')
        raise ApiError(response)

    logger.info('Successfully changed user password', token=token)
    return redirect(url_for('passwords_bp.reset_password_confirmation'))


@passwords_bp.route('/reset-password/confirmation', methods=['GET'])
def reset_password_confirmation():
    return render_template('passwords/reset-password.confirmation.html', _theme='default')