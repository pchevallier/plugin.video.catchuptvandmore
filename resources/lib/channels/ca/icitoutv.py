# -*- coding: utf-8 -*-
# Copyright: (c) 2018, SylvainCecchetto
# GNU General Public License v2.0+ (see LICENSE.txt or https://www.gnu.org/licenses/gpl-2.0.txt)

# This file is part of Catch-up TV & More

from __future__ import unicode_literals
import json
import requests
import os
import base64
import time
import inputstreamhelper
import urlquick
import http.cookiejar as cookielib
import sys
import gzip

from codequick import Listitem, Resolver, Route
from kodi_six import xbmc, xbmcgui, xbmcvfs, xbmcaddon
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.parse import urlencode, quote
from io import StringIO as StringIO 
from resources.lib.menu_utils import item_post_treatment
from resources.lib import resolver_proxy, web_utils

GENERIC_HEADERS = {'User-Agent': web_utils.get_random_ua()}

HOST = 'services.radio-canada.ca'

URL_ROOT = 'https://ici.tou.tv'

URL_RADIOCANADA = 'https://' + HOST
URL_SERVICES = URL_RADIOCANADA+'/ott/catalog/v2/toutv/%s'
URL_SUBSCRIPTION = URL_RADIOCANADA+'/ott/subscription/v2/toutv/subscriber/profile?device=web'
URL_VIDEO = URL_RADIOCANADA+'/media/validation/v2/'

FRONTEND_CONFIG_URL = 'https://rcmnb2cprod.b2clogin.com/rcmnb2cprod.onmicrosoft.com/B2C_1A_ExternalClient_FrontEnd_Login/oauth2/v2.0/authorize?client_id=ebe6e7b0-3cc3-463d-9389-083c7b24399c&redirect_uri=https%3A%2F%2Fici.tou.tv%2Fauth-changed&scope=openid%20offline_access%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Femail%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fid.account.create%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fid.account.delete%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fid.account.info%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fid.account.modify%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fid.account.reset-password%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fid.account.send-confirmation-email%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fid.write%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fmedia-drmt%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fmedia-meta%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fmedia-validation%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fmedia-validation.read%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fmetrik%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Foidc4ropc%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fott-profiling%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fott-subscription%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fprofile%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fsubscriptions.validate%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Fsubscriptions.write%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Ftoutv%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Ftoutv-presentation%20https%3A%2F%2Frcmnb2cprod.onmicrosoft.com%2F84593b65-0ef6-4a72-891c-d351ddd50aab%2Ftoutv-profiling&response_type=id_token%20token'
URL_LICENCE_KEY = 'https://lic.drmtoday.com/license-proxy-widevine/cenc/|Content-Type=&User-Agent=Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3041.0 Safari/537.36&Host=lic.drmtoday.com&x-dt-auth-token=%s|R{SSM}|JBlicense'
B2CLOGIN_API='https://rcmnb2cprod.b2clogin.com/rcmnb2cprod.onmicrosoft.com/B2C_1A_ExternalClient_FrontEnd_Login'
GET_SELF_ASSERTED_URL = B2CLOGIN_API+'/SelfAsserted?tx=StateProperties=%s&p=B2C_1A_ExternalClient_FrontEnd_Login'
CLIENT_ID = 'ebe6e7b0-3cc3-463d-9389-083c7b24399c'
AUTHORIZATION_URL= B2CLOGIN_API + '/oauth2/v2.0/authorize?client_id='+CLIENT_ID+'&' 


authorization_data = {
"redirect_uri": URL_ROOT + "/auth-changed",
"scope":"openid offline_access \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/media-drmt \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/media-meta \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/media-validation \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/media-validation.read \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/oidc4ropc \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/ott-profiling \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/ott-subscription \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/profile \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/subscriptions.validate \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/subscriptions.write \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/toutv \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/toutv-presentation \
https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/toutv-profiling",
"response_type":"id_token token"
}
# Unecessary Autorization Options
#https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/email \
#https://rcmnb2cprod.onmicrosoft.com/84593b65-0ef6-4a72-891c-d351ddd50aab/metrik \


CombinedSigninAndSignup_diags = {
    "pageViewId": "fef7143d-a216-4fa8-a066-cbfa7c315a93",
    "pageId": "CombinedSigninAndSignup",
    "trace": [
        {
            "ac": "T005",
            "acST": 1730670125,
            "acD": 0
        },
        {
            "ac": "T021 - URL:https://micro-sites.radio-canada.ca/b2cpagelayouts/login/password",
            "acST": 1730670125,
            "acD": 40
        },
        {
            "ac": "T019",
            "acST": 1730670125,
            "acD": 2
        },
        {
            "ac": "T004",
            "acST": 1730670125,
            "acD": 0
        },
        {
            "ac": "T003",
            "acST": 1730670125,
            "acD": 1
        },
        {
            "ac": "T035",
            "acST": 1730670125,
            "acD": 0
        },
        {
            "ac": "T030Online",
            "acST": 1730670125,
            "acD": 0
        },
        {
            "ac": "T002",
            "acST": 1730670148,
            "acD": 0
        },
        {
            "ac": "T018T010",
            "acST": 1730670147,
            "acD": 348
        }
    ]
}

SelfAsserted_diags={
    "pageViewId": "ced09dac-0687-48c9-87de-f5a60d4ae43f",
    "pageId": "SelfAsserted",
    "trace": [
        {
            "ac": "T005",
            "acST": 1730670689,
            "acD": 1
        },
        {
            "ac": "T021 - URL:https://micro-sites.radio-canada.ca/b2cpagelayouts/login/email",
            "acST": 1730670689,
            "acD": 64
        },
        {
            "ac": "T019",
            "acST": 1730670689,
            "acD": 2
        },
        {
            "ac": "T004",
            "acST": 1730670689,
            "acD": 3
        },
        {
            "ac": "T003",
            "acST": 1730670689,
            "acD": 1
        },
        {
            "ac": "T035",
            "acST": 1730670689,
            "acD": 0
        },
        {
            "ac": "T030Online",
            "acST": 1730670689,
            "acD": 0
        },
        {
            "ac": "T017T010",
            "acST": 1730671535,
            "acD": 447
        },
        {
            "ac": "T002",
            "acST": 1730671536,
            "acD": 0
        },
        {
            "ac": "T017T010",
            "acST": 1730671535,
            "acD": 448
        }
    ]
}

def validate_expiration(auth_token: str) -> bool:

    decrypted_auth = base64.b64decode(auth_token.split(".")[1] + "==").decode(encoding="ascii")

    time_auth = json.loads(decrypted_auth)["exp"]
    
    if time_auth < time.time():
        return False
    
    return True

def get_x_token(access_token: str):

    token = ""
    headers = {
        "Authorization": access_token,
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.1"

    }
    url = URL_SUBSCRIPTION 
    r = requests.get(url, headers=headers)
    resp = r.json()


    if r.status_code == 200 :
        tier = resp['tier']
        statsMetas = resp['statsMetas']
        token = resp['claimsToken']

    return token

def save_authorization_token(data, filename):
    # Get the path to the plugin's userdata folder using xbmcvfs.translatePath
    addon = xbmcaddon.Addon()
    userdata_path = xbmcvfs.translatePath(addon.getAddonInfo('profile'))  # Ensures cross-platform compatibility

    # Ensure the directory exists
    if not xbmcvfs.exists(userdata_path):
        xbmcvfs.mkdirs(userdata_path)

    # Full file path
    file_path = os.path.join(userdata_path, filename)

    # Save JSON data to the file
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def load_authorization_token(filename)->tuple[str,str]:
    # Get the path to the plugin's userdata folder using xbmcvfs.translatePath
    addon = xbmcaddon.Addon()
    userdata_path = xbmcvfs.translatePath(addon.getAddonInfo('profile'))

    # Full file path
    file_path = os.path.join(userdata_path, filename)

    # Check if the file exists
    if not xbmcvfs.exists(file_path):
        return ""

    # Load JSON data from the file
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    return data

def BYTES_PY2(bytesOrString):
    if sys.version_info.major >= 3:
        return bytes(bytesOrString, encoding='utf8')
    else:
        return bytesOrString

def handleHttpResponse(response):
    if sys.version_info.major >= 3:
        if response.info().get('Content-Encoding') == 'gzip':
            f = gzip.GzipFile(fileobj=response)
            data = f.read()
            return data
        else:
            data = response.read()
            return data
    else:
        if response.info().get('Content-Encoding') == 'gzip':
            buf = StringIO( response.read() )
            f = gzip.GzipFile(fileobj=buf)
            data = f.read()
            return data
        else:
            return response.read()

def GET_ACCESS_TOKEN_MS(modeLogin, params ):

    csrf = None
    
    for c in params[0]:
        if c.name == "x-ms-cpim-csrf":
            csrf = c.value

    url = None
    StateProperties = params[1].decode('utf-8')

    if modeLogin == True:
        CombinedSigninAndSignup = '&p=B2C_1A_ExternalClient_FrontEnd_Login&diags='+ json.dumps(CombinedSigninAndSignup_diags)
        encoded_string = quote(CombinedSigninAndSignup, safe='=&')
        url = B2CLOGIN_API + "/api/CombinedSigninAndSignup/confirmed?rememberMe=true&csrf_token=" + csrf + "&tx=StateProperties=" + StateProperties + encoded_string
    else:
        SelfAsserted = '&p=B2C_1A_ExternalClient_FrontEnd_Login&diags=' + json.dumps(SelfAsserted_diags)
        encoded_string = quote(SelfAsserted, safe='=&')
        url = B2CLOGIN_API + "/api/SelfAsserted/confirmed/?csrf_token=" + csrf + "&tx=StateProperties=" + StateProperties + encoded_string


    cookie_handler = HTTPCookieProcessor(params[0])
    opener = build_opener(cookie_handler)

    request = Request(url)
    request.get_method = lambda: "GET"
    
    response = opener.open(request)
    text = handleHttpResponse(response)
    for c in params[0]:
        if c.name == "x-ms-cpim-csrf":
            csrf = c.value
    return params, response.geturl()


def GET_SELF_ASSERTED( params, data ):

    csrf = None
    
    for c in params[0]:
        if c.name == "x-ms-cpim-csrf":
            csrf = c.value
    StateProperties = params[1].decode('utf-8')
    url = GET_SELF_ASSERTED_URL % StateProperties
    cookie_handler = HTTPCookieProcessor(params[0])
    opener = build_opener(cookie_handler)

    opener.addheaders = [
    ('X-CSRF-TOKEN', csrf)
    ]

    post_data = urlencode(data)

    request = Request(url, data=BYTES_PY2(post_data))
    request.get_method = lambda: "POST"
    
    response = opener.open(request)

    rawresp = handleHttpResponse(response)
    response_dict = json.loads(rawresp.decode('utf-8'))

    if response_dict.get("status") != "200":
       xbmcgui.Dialog().ok("icitoutv",response_dict.get("message"))
       return "",""

    return params[0], params[1]

def GET_AUTHORIZE(url):

    cookiejar = cookielib.LWPCookieJar()
    cookie_handler = HTTPCookieProcessor(cookiejar)
    opener = build_opener(cookie_handler)

    request = Request(url)
    request.get_method = lambda: "GET"
    
    response = opener.open(request)
    text = handleHttpResponse(response)

    parts = text.split(BYTES_PY2("StateProperties="), 1)
    parts = parts[1].split(BYTES_PY2("\""), 1)
    state = parts[0]

    return cookiejar, state

def get_access_token(email: str, password: str):

    encoded_data = urlencode(authorization_data, quote_via=quote)

    params = GET_AUTHORIZE(AUTHORIZATION_URL + encoded_data)

    data = {'email': email, 'request_type': 'RESPONSE'}
    valassert1 = GET_SELF_ASSERTED(params, data)
    if valassert1[1] == "":
       return ""
    
    tokenS1 = GET_ACCESS_TOKEN_MS(False ,valassert1)

    data = {'email': email, 'request_type': 'RESPONSE', 'password': password}
    valassert2 = GET_SELF_ASSERTED(tokenS1[0], data)
    if valassert2[1] == "":
       return ""

    tokenS2 = GET_ACCESS_TOKEN_MS(True, valassert2)

    tokenS3 = tokenS2[1].split("access_token=")
    access_token = tokenS3[1].split("&token_type")
    accessToken = access_token[0]

    return "Bearer " + accessToken

def get_token(plugin):
    access_token = load_authorization_token("icitoutv_authorization_token.json")
    if access_token == "" or not validate_expiration(json.dumps(access_token)) :
       email = plugin.setting.get_string('icitoutv.login')
       password = plugin.setting.get_string('icitoutv.password')
       if email == "" :
         return {"Authorization" : "", "x-claims-token" : ""}
       a_token = get_access_token(email, password)
       if a_token == "": 
         return {"Authorization" : "", "x-claims-token" : ""}
       x_token = get_x_token(a_token)
       headers = {"Authorization" : a_token, "x-claims-token" : x_token}
       save_authorization_token(headers, "icitoutv_authorization_token.json")
       access_token = headers

    return access_token

@Route.register
def list_categories(plugin, item_id, **kwargs):
    params = {
        'device': 'web'
    }
    resp = urlquick.get(URL_SERVICES % 'browse', headers=GENERIC_HEADERS, params=params, max_age=-1)
    root = json.loads(resp.text)

    for category in root['formats']:
        item = Listitem()
        item.label = category['title']
        item.art['thumb'] = item.art['landscape'] = category['image']['url']
        url = category['url'].replace('categorie', 'category')
        item.set_callback(list_programs, url=url, page='1')
        item_post_treatment(item)
        yield item


@Route.register
def list_programs(plugin, url, page, **kwargs):
    token = get_token(plugin)

    params = {
        'device': 'web',
        'pageNumber': page,
        'pageSize': '80'
    }
    resp = urlquick.get(URL_SERVICES % url, headers=GENERIC_HEADERS, params=params, max_age=-1)
    json_parser = json.loads(resp.text)['content'][0]
    nbpages = json_parser['items']['totalPages']
    page = json_parser['items']['pageNumber']

    for program in json_parser["items"]["results"]:
        if program["tier"] == 'Standard' or (token['Authorization'] and program["tier"] == 'Member'):
            item = Listitem()
            program_url = program['url']
            prog_type = program['type']
            item.label = program["title"]
            item.art['thumb'] = item.art['landscape'] = program["images"]["background"]["url"]
            item.info["plot"] = program["description"]
            item.set_callback(list_seasons, program_url, prog_type=prog_type)
            item_post_treatment(item)
            yield item

    if int(page) < int(nbpages):
        page = str(int(page) + 1)
        yield Listitem.next_page(url=url, page=page)


@Route.register
def list_seasons(plugin, url, prog_type, **kwargs):
    token = get_token(plugin)
    params = {'device': 'web'}
    program_url = prog_type + '/' + url
    resp = urlquick.get(URL_SERVICES % program_url, headers=GENERIC_HEADERS, params=params, max_age=-1)
    json_parser = json.loads(resp.text)

    for season in json_parser['content'][0]['lineups']:
        if season["tier"] == 'Standard' or (token['Authorization'] and season["tier"] == 'Member'):
            item = Listitem()
            item.label = season['title']
            season_url = prog_type + '/' + season['url']
            item.set_callback(list_episodes, season_url=season_url, season_title=season['title'])
            item_post_treatment(item)
            yield item


@Route.register
def list_episodes(plugin, season_url, season_title, **kwargs):
    token = get_token(plugin)
    params = {'device': 'web'}
    resp = urlquick.get(URL_SERVICES % season_url, headers=GENERIC_HEADERS, params=params, max_age=-1)
    json_parser = json.loads(resp.text)

    for season in json_parser['content'][0]['lineups']:
        if season_title.replace(" ", "") == season['title'].replace(" ", ""):
          for episode in season['items']:
              if episode["tier"] == 'Standard' or (token['Authorization'] and episode["tier"] == 'Member'):
                  item = Listitem()
                  video_id = episode['idMedia']
                  item.label = episode["title"]
                  item.art['thumb'] = item.art['landscape'] = episode["images"]["card"]["url"]
                  if "infoTitle" in episode:
                      item.info["plot"] = "["+episode["infoTitle"]+"]"+episode["description"]
                  else:
                      item.info["plot"] = episode["description"]
                  item.set_callback(get_video_url, video_id=video_id)
                  item_post_treatment(item)
                  yield item


@Resolver.register
def get_video_url(plugin, video_id, download_mode=False, **kwargs):
    token = get_token(plugin)
    params = {
        'appCode': 'toutv',
        'connectionType': 'hd',
        'deviceType': 'multiams',
        'idMedia': video_id,
        'multibitrate': 'false',
        'output': 'json',
        'tech': 'dash',
        'manifestType': 'desktop',
    }
    headers = {
        'Authorization': token['Authorization'], 
        'x-claims-token': token['x-claims-token'], 
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': web_utils.get_random_ua(),
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'en-US,en;q=0.9,fr-FR;q=0.8,fr;q=0.7',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'DNT' : '1',
        'Host': HOST,
        'Origin': URL_ROOT,
        'Pragma': 'no-cache',
        'Referer': URL_ROOT,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode' : 'cors',
        'Sec-Fetch-Site' : 'cross-site',
        'sec-ch-ua' : web_utils.get_random_ua(),
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Unknown"',
        'sec-gpc': '1'
    }
    resp = urlquick.get(URL_VIDEO, headers=headers, params=params, max_age=-1)
    json_parser = json.loads(resp.text)

    if json_parser['errorCode'] != 0 :
        xbmc.log(f"get_video_url: {json_parser}", level=xbmc.LOGERROR)
        xbmcgui.Dialog().ok("icitoutv",json_parser["message"])
        return False

    video_url = json_parser['url']

    for item in json_parser['params']:
        if 'name' in item:
            if item['name'] == 'widevineLicenseUrl':
                license_url = item['value']
            if item['name'] == 'widevineAuthToken':
                token = item['value']

    headers = {
        'User-Agent': web_utils.get_random_ua(),
        'Authorization': token
    }

    is_helper = inputstreamhelper.Helper('mpd', drm='widevine')
    if not is_helper.check_inputstream():
        xbmc.log(f"inputstreamhelper: unable to support mpd file format with widevine", level=xbmc.LOGERROR)
        return False

    final_video_url = json_parser["url"]
    token =  next(param["value"] for param in json_parser["params"] if param["name"] == "playreadyAuthToken")

    return resolver_proxy.get_stream_with_quality(plugin, video_url=final_video_url, license_url=URL_LICENCE_KEY % token, manifest_type='mpd')

@Resolver.register
def get_live_url(plugin, item_id, **kwargs):

    resp = urlquick.get('https://services.radio-canada.ca/media/validation/v2/?appCode=medianetlive&connectionType=hd&deviceType=ipad&idMedia=26&multibitrate=true&output=json&tech=hls&manifestVersion=2')
    json_parser = json.loads(resp.text)
    url_video = json_parser["url"]
    xbmc.log(f"get_live_url: {url_video}", level=xbmc.LOGINFO)

    return resolver_proxy.get_stream_with_quality(plugin, video_url=url_video, manifest_type="hls")