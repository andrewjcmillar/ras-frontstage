import json
import logging

from flask import flash, Markup, redirect, render_template, request, url_for
from structlog import wrap_logger

from frontstage.common.authorisation import jwt_authorization
from frontstage.controllers import conversation_controller
from frontstage.models import SecureMessagingForm
from frontstage.views.secure_messaging import secure_message_bp


logger = wrap_logger(logging.getLogger(__name__))


@secure_message_bp.route('/create-message/', methods=['GET', 'POST'])
@jwt_authorization(request)
def create_message(session):
    survey = request.args['survey']
    ru_ref = request.args['ru_ref']
    party_id = session['party_id']
    form = SecureMessagingForm(request.form)
    if request.method == 'POST' and form.validate():
        logger.info("Form validation successful", party_id=party_id)
        sent_message = send_message(party_id, survey, ru_ref)
        thread_url = url_for("secure_message_bp.view_conversation",
                             thread_id=sent_message['thread_id']) + "#latest-message"
        flash(Markup('Message sent. <a href={}>View Message</a>'.format(thread_url)))
        return redirect(url_for('secure_message_bp.view_conversation_list'))

    else:
        return render_template('secure-messages/secure-messages-view.html',
                               ru_ref=ru_ref, survey=survey,
                               form=form, errors=form.errors, message={})


def send_message(party_id, survey, ru_ref):
    logger.info('Attempting to send message', party_id=party_id)
    form = SecureMessagingForm(request.form)

    subject = form['subject'].data if form['subject'].data else form['hidden_subject'].data
    message_json = {
        "msg_from": party_id,
        "msg_to": ['GROUP'],
        "subject": subject,
        "body": form['body'].data,
        "thread_id": form['thread_id'].data,
        "ru_id": ru_ref,
        "survey": survey,
    }

    response = conversation_controller.send_message(json.dumps(message_json))

    logger.info('Secure message sent successfully',
                message_id=response['msg_id'], party_id=party_id)
    return response
