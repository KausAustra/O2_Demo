import html
import requests
import re
import logging
import getpass

def check(source, session, timeout):
    try:
        r = session.get(
            f"{source['url']}/api/account/userinfo",
            timeout=timeout
        )
        return r.ok
    except Exception:
        return False


def auth(source, timeout=1200):
    if 'user_input_string' not in globals() or not user_input_string:
        user_input_string = getpass.getpass("Введите пароль: ")
    def f(s, t):
        r = s.post(
            f'{source["url"]}:3334/ui/login',
            json=dict(
                authType=1,
                username=source["user"],
                password=user_input_string
            ), 
            verify=False,
            timeout=t
        )
        return r
    s = requests.Session()
    s.verify = False
    try:
        r = f(s, timeout)
        if r.status_code == 400:
            r = f(s, timeout)
        logging.info(f"Auth at {source['name']} core, status: {r.status_code}")
        r = s.get(
            f'{source["url"]}/account/login?returnUrl=/#/authorization/landing',
            verify=False
        )
        logging.info(f"Auth at {source['name']} mpx, status: {r.status_code}")
        while '<form' in r.text:
            form_action, form_data = parse_form(r.text)
            r = s.post(
                form_action,
                data=form_data,
                verify=False,
                timeout=timeout
            )
    except Exception as e:
        logging.error(str(e))
    if not check(source, s, timeout):
        logging.error(f"Auth at {source['name']} - {source['url']} failed")
    else:
        return s


def parse_form(data):
    return re.search('action=[\'"]([^\'"]*)[\'"]', data).groups()[0], {
        item.groups()[0]: html.unescape(item.groups()[1])
        for item in re.finditer('name=[\'"]([^\'"]*)[\'"] value=[\'"]([^\'"]*)[\'"]', data)
    }
