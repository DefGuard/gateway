{% if helpers.exists("OPNsense.defguardgateway.general.Enabled") and OPNsense.defguardgateway.general.Enabled == '1' %}
defguard_enable="YES"
{% else %}
defguard_enable="NO"
{% endif %}
