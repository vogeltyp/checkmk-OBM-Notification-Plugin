# README
## Installation
- to use this plugin place a copy of the notify_obm.py and config.json.dist in the checkmk notification-plugins-directory
`/opt/omd/sites/testsite/local/share/check_mk/notifications`
- write your OBM-URL, user and a DES-Hash of you Password to the `config.json.dist` and rename it to `config.json`
- change the owner to your checkmk-Site-User and the permissions to 400 (readonly for that user)
- make the script executeable `chmod +x notify_obm.py` and own it to your checkmk-Site-User
- modify your notification rule in checkmk and select "OBM-Notification" as "Notification Method"

That's it.

## Error-List

- ERROR#001_CONFIG_MISSING:
  - the config.json must be placed in the same path as the script
- ERROR#002_SENTFAULT:
  - the event could not be sent to the server.<br>
    If debugging in config.json is enabled you will see the XML-Output which has been sent.
- ERROR#003_WRONG_SEVERITY
  - only the defined severity-levels in config.json are allowed by OBM
- ERROR#004_WRONG_PRIORITY
  - only the defined priority-levels in config.json are allowed by OBM
- ERROR#005_ENV_MISSING
  - the script could not find the ENV-Vars sent by checkmk
- ERROR#006_WRONG_FILEPERMISSION
  - the config.json MUST belong to the site-owner and MUST NOT have any other permission than read-rights