<h2>Configuration</h2>

<script type="text/javascript">
$( document ).ready(function() {
    mapDataToFormUI({"frm_GeneralSettings": "/api/defguardgateway/settings/get"}).done(function(data) {
    	updateServiceControlUI("defguardgateway");
    });

    $("#saveAct").click(function(){
        $("#responseMsg").removeClass("hidden");
        saveFormToEndpoint(url="/api/defguardgateway/settings/set", formid='frm_GeneralSettings', callback_ok=function() {
            updateServiceControlUI("defguardgateway");
    		ajaxCall(url="/api/defguardgateway/service/reconfigure", sendData={}, callback=function(data, status) {
    			$("#responseMsg").html(data["status"]);
      		});
    		ajaxCall(url="/api/defguardgateway/service/restart", sendData={}, callback=function(data, status) {
    			updateServiceControlUI("defguardgateway");
    		});
        });
    });

    $("#startAct").click(function () {
        stdDialogConfirm(
            '{{ lang._("Confirm gateway restart") }}',
            '{{ lang._("Do you want to restart Defguard Gateway?") }}',
            '{{ lang._("Yes") }}', '{{ lang._("Cancel") }}', function () {
                $("#startAct").addClass("fa fa-spinner");
				$("#responseMsg").removeClass("hidden");
                ajaxCall(url="/api/defguardgateway/service/restart", sendData={}, callback=function(data,status) {
                    $("#startAct").removeClass("fa fa-spinner fa-pulse");
    				$("#responseMsg").html(data['status']);
    				updateServiceControlUI("defguardgateway");
          		});
        });
    });
});
</script>
<div class="alert alert-info hidden" role="alert" id="responseMsg">
</div>

<div class="col-md-12">
    {{ partial("layout_partials/base_form", ['fields':generalForm,'id':'frm_GeneralSettings']) }}
</div>

<div class="col-md-12">
	<button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b></button>
	<button class="btn btn-primary" id="startAct" type="button"><b>{{ lang._('Start/Restart') }}</b></button>
</div>
