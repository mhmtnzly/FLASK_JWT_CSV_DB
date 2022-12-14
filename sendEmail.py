from azure.communication.email import EmailClient, EmailContent, EmailAddress, EmailMessage, EmailRecipients


class Email:
    def __init__(self, connection_string) -> None:

        connection_string = connection_string
        self.client = EmailClient.from_connection_string(connection_string)
        self.sender = "FlaskApp@7af7529d-dab6-4612-9045-5c0f2a551152.azurecomm.net"

    def emailSend(self, fileName, to, body, userName):
        content = EmailContent(
            subject=f"Progress of the {fileName} file.",
            plain_text="This is the body",
            html=f"<html><h1>{body}</h1></html>",
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
