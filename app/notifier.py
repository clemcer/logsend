import requests
import logging
import urllib.parse
import apprise
from load_config import GlobalConfig



logging.getLogger(__name__)

def send_apprise_notification(url, container_name, message, keyword=None, file_name=None):
    apobj = apprise.Apprise()

    apobj.add(url)
    message = ("This message had to be shortened: \n" if len(message) > 1900 else "") + message[:1900]

    if keyword is None:
        title = f"{container_name}"
    else:
        title = f"'{keyword}' found in {container_name}"
    try: 
        if file_name is None:
            apobj.notify(
                title=title,
                body=message,
            )
        else:
            apobj.notify(
                title=title,
                body=message,
                attach=file_name
            )
        logging.info("Apprise-Notification sent successfully")
    except Exception as e:
        logging.error("Error while trying to send apprise-notification: %s", e)


def send_ntfy_notification(config, container_name, message, keyword=None, file_name=None):
    """
    Sendet eine Benachrichtigung an den ntfy-Server.
    """
    ntfy_url = config.notifications.ntfy.url
    
    if container_name in [c for c in config.containers]:
        ntfy_topic = config.containers[container_name].ntfy_topic or config.notifications.ntfy.topic
        ntfy_tags = config.containers[container_name].ntfy_tags or config.notifications.ntfy.tags
        ntfy_priority = config.containers[container_name].ntfy_priority or config.notifications.ntfy.priority
    else:
        ntfy_topic = config.notifications.ntfy.topic
        ntfy_tags = config.notifications.ntfy.tags
        ntfy_priority = config.notifications.ntfy.priority

    message = ("This message had to be shortened: \n" if len(message) > 3900 else "") + message[:3900]


    headers = {
        "Tags": f"{ntfy_tags}",
        "Icon": "https://raw.githubusercontent.com/clemcer/loggifly/main/images/icon.png",
        "Priority": f"{ntfy_priority}"
    }
    if config.notifications.ntfy.token:
        headers["Authorization"] = f"Bearer {config.notifications.ntfy.token.get_secret_value()}"

    if keyword is None:
        headers["Title"] = f"{container_name}"
    else:
        headers["Title"] = f"'{keyword}' found in {container_name}"


    message_text = f"{message}"
    
    try:
        if file_name:
            logging.debug("Message WITH file is being sent")
            headers["Filename"] = file_name
            with open(file_name, "rb") as file:
                if len(message_text) < 199:
                    response = requests.post(
                        f"{ntfy_url}/{ntfy_topic}?message={urllib.parse.quote(message_text)}",
                        data=file,
                        headers=headers
                    )
                else:
                    response = requests.post(
                        f"{ntfy_url}/{ntfy_topic}",
                        data=file,
                        headers=headers
                    )
        else:
            logging.debug("Message WITHOUT file is being sent")
            response = requests.post(
                f"{ntfy_url}/{ntfy_topic}", 
                data=message_text,
                headers=headers
            )
        if response.status_code == 200:
            logging.info("Ntfy-Notification sent successfully")
        else:
            logging.error("Error while trying to send ntfy-notification: %s", response.text)
    except requests.RequestException as e:
        logging.error("Error while trying to connect to ntfy: %s", e)



def send_notification(config: GlobalConfig, container_name, message, keyword=None, file_name=None):
    if (config.notifications and config.notifications.ntfy and config.notifications.ntfy.url and config.notifications.ntfy.topic):
        send_ntfy_notification(config, container_name, message, keyword, file_name)


    if (config.notifications and config.notifications.apprise and config.notifications.apprise.url):
        apprise_url = config.notifications.apprise.url.get_secret_value()
        send_apprise_notification(apprise_url, container_name, message, keyword, file_name)
   

   