# README
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
  
