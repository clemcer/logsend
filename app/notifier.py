import requests
import logging
import os
import urllib.parse
import apprise



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
        logging.info("Apprise-Notification sent successfully: %s", message)
    except Exception as e:
        logging.error("Error while trying to send apprise-notification: %s", e)


def send_ntfy_notification(config, container_name, message, keyword=None, file_name=None):
    """
    Sendet eine Benachrichtigung an den ntfy-Server.
    """
    ntfy_url = config["notifications"]["ntfy"]["url"]
    ntfy_token = config["notifications"]["ntfy"]["token"]

    if isinstance(config.get("containers").get(container_name, {}), dict):
        ntfy_topic = config.get("containers", {}).get(container_name, {}).get("ntfy_topic") or config["notifications"].get("ntfy", {}).get("topic", "")
        ntfy_tags = config.get("containers", {}).get(container_name, {}).get("ntfy_tags") or config["notifications"].get("ntfy", {}).get("tags", "warning")
        ntfy_priority = config.get("containers", {}).get(container_name, {}).get("ntfy_priority") or config["notifications"].get("ntfy", {}).get("priority", "3")

    else:
        ntfy_topic=  config["notifications"].get("ntfy", {}).get("topic", "")
        ntfy_tags = config["notifications"].get("ntfy", {}).get("tags", "warning")
        ntfy_priority = config["notifications"].get("ntfy", {}).get("priority", "warning")


   

    if not ntfy_url or not ntfy_topic or not ntfy_token:
        logging.error("Ntfy-Konfiguration fehlt. Benachrichtigung nicht möglich.")
        return

    message = ("This message had to be shortened: \n" if len(message) > 3900 else "") + message[:3900]

    headers = {
        "Authorization": f"Bearer {ntfy_token}",
        "Tags": f"{ntfy_tags}",
        "Icon": "https://raw.githubusercontent.com/clemcer/logsend/refs/heads/main/icon.png?token=GHSAT0AAAAAAC5ITTW6BMYID4P2XDAGI46MZ5LMHGA",
        "Priority": f"{ntfy_priority}"
    }

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
            logging.info("Ntfy-Notification sent successfully: %s", message)
        else:
            logging.error("Error while trying to send ntfy-notification: %s", response.text)
    except requests.RequestException as e:
        logging.error("Error while trying to connect to ntfy: %s", e)



def send_notification(config, container_name, message, keyword=None, file_name=None):
    ntfy_url = config["notifications"]["ntfy"]["url"]
    ntfy_token = config["notifications"]["ntfy"]["token"]
    if ntfy_url and ntfy_token:
        send_ntfy_notification(config, container_name, message, keyword, file_name)

    apprise_url = config["notifications"]["apprise"]["url"]
    if apprise_url:
        send_apprise_notification(apprise_url, container_name, message, keyword, file_name)

    if file_name is not None:
        if os.path.exists(file_name):
            os.remove(file_name)
            logging.debug(f"Die Datei {file_name} wurde gelöscht.")
        else:
            logging.debug(f"Die Datei {file_name} existiert nicht.")
    
    # if not ntfy_url or not ntfy_token or not apprise_url:
    #     logging.error("No notification service configured. You can not receive notifications at the moment.")
    