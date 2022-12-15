from azure.communication.email import EmailClient, EmailContent, EmailAddress, EmailMessage, EmailRecipients


class Email:
    def __init__(self, connection_string) -> None:

        connection_string = connection_string
        self.client = EmailClient.from_connection_string(connection_string)
        self.sender = "FlaskApp@7af7529d-dab6-4612-9045-5c0f2a551152.azurecomm.net"

    def emailSendForFile(self, to, body, userName):
        contentBody = ''
        if len(body) == 1:
            filename = body[0]['filename']
            subject_ = f"Progress of the {filename} file"
        else:
            subject_ = "Progress of files you added."
        for file in body:
            if file['success']:
                contentBody += f"<p>{file['filename']} was added successfully.</p>"
            else:
                contentBody += f"<p>{file['filename']} was not added.</p>"

        content = EmailContent(
            subject=subject_,
            plain_text="This is the body",
            html=f"<html><h5>Progress of files.</h5>{contentBody}</html>",
        )

        address = EmailAddress(
            email=to, display_name=userName)

        message = EmailMessage(
            sender=self.sender,
            content=content,
            recipients=EmailRecipients(to=[address])
        )
        response = self.client.send(message)
        return response

    def confirmationMail(self, to, body, userName):
        subject_ = f"Confirmation of {userName}"
        content = EmailContent(
            subject=subject_,
            plain_text="This is the body",
            html=f"<html><h5>{body}</h5></html>",
        )

        address = EmailAddress(
            email=to, display_name=userName)

        message = EmailMessage(
            sender=self.sender,
            content=content,
            recipients=EmailRecipients(to=[address])
        )
        response = self.client.send(message)
        return response
