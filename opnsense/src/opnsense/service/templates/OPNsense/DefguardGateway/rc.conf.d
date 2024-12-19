{% if helpers.exists("OPNsense.defguardgateway.general.Enabled") and OPNsense.defguardgateway.general.Enabled == '1' %}
defguard_gateway_enable="YES"
{% else %}
defguard_gateway_enable="NO"
{% endif %}
