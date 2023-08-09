<h2> Configuration</h2>
<script type="text/javascript">
    $( document ).ready(function() {
        var data_get_map = {'frm_GeneralSettings':"/api/defguardgateway/settings/get"};
        mapDataToFormUI(data_get_map).done(function(data){
            // place actions to run after load, for example update form styles.
					updateServiceControlUI('defguardgateway');
        });

        // link save button to API set action
        $("#saveAct").click(function(){
            $("#responseMsg").removeClass("hidden");
            saveFormToEndpoint(url="/api/defguardgateway/settings/set", formid='frm_GeneralSettings',callback_ok=function(){
								updateServiceControlUI('defguardgateway');
								ajaxCall(url="/api/defguardgateway/service/reload", sendData={},callback=function(data,status) {
										$("#responseMsg").html(data['status']);
										// action to run after reload
								});
                // Reload configuration after save.
								ajaxCall(url="/api/defguardgateway/service/reset", sendData={},callback=function(data,status) {
										// action to run after reload
										updateServiceControlUI('defguardgateway');
							});
            });
        });
    $("#startAct").click(function () {
        stdDialogConfirm(
            '{{ lang._('Confirm gateway reset') }}',
            '{{ lang._('Do you want to reset the Defguard Gateway?') }}',
            '{{ lang._('Yes') }}', '{{ lang._('Cancel') }}', function () {
                $("#startAct").addClass("fa fa-spinner");
								$("#responseMsg").removeClass("hidden");
                ajaxCall(url="/api/defguardgateway/service/reset", sendData={}, callback=function(data,status) {
                    $("#startAct").removeClass("fa fa-spinner fa-pulse");
										$("#responseMsg").html(data['status']);
										updateServiceControlUI('defguardgateway');
            		});
        });
    });
    });

</script>
<div class="alert alert-info hidden" role="alert" id="responseMsg">

</div>

<div  class="col-md-12">
    {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_GeneralSettings'])}}
</div>

<div class="row">
	<div class="col-md-1">
			<button class="btn btn-primary"  id="saveAct" type="button"><b>{{ lang._('Save') }}</b></button>
	</div>

	<div class="col-md-1">
			<button class="btn btn-primary"  id="startAct" type="button"><b>{{ lang._('Start/Restart') }}</b></button>
	</div>
</div>
