from azure.communication.email import EmailClient
from azure.core.credentials import AzureKeyCredential


class Email:
    def __init__(self) -> None:

        self.credential = AzureKeyCredential("<api_key>")
        self.endpoint = "https://<resource-name>.communication.azure.com/"
        self.client = EmailClient(self.endpoint, self.credential)

    def emailSend(self, fileName, to, sender, body, userName):
        content = self.EmailContent(
            subject=f"Progress of the {fileName} file",
            plain_text="This is the body",
            html=f"<html><h1>{body}</h1></html>",
        )

        address = self.EmailAddress(
            email=to, display_name=userName)

        message = self.EmailMessage(
            sender=sender,
            content=self.content,
            recipients=self.EmailRecipients(to=[address])
        )
        response = self.client.send(message)
        return response
