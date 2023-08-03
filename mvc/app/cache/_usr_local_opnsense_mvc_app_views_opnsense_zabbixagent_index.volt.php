

<script>
$( document ).ready(function() {
    var data_get_map = {'frm_zabbixagent':"/api/zabbixagent/settings/get"};

    // load initial data
    mapDataToFormUI(data_get_map).done(function(){
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
        updateServiceControlUI('zabbixagent');
    });

    /***********************************************************************
     * link grid actions
     **********************************************************************/

    $("#grid-userparameters").UIBootgrid(
        {   search:'/api/zabbixagent/settings/searchUserparameters',
            get:'/api/zabbixagent/settings/getUserparameter/',
            set:'/api/zabbixagent/settings/setUserparameter/',
            add:'/api/zabbixagent/settings/addUserparameter/',
            del:'/api/zabbixagent/settings/delUserparameter/',
            toggle:'/api/zabbixagent/settings/toggleUserparameter/',
            options: {
                rowCount:[10,25,50,100,500,1000]
            }
        }
    );

    $("#grid-aliases").UIBootgrid(
        {   search:'/api/zabbixagent/settings/searchAliases',
            get:'/api/zabbixagent/settings/getAlias/',
            set:'/api/zabbixagent/settings/setAlias/',
            add:'/api/zabbixagent/settings/addAlias/',
            del:'/api/zabbixagent/settings/delAlias/',
            toggle:'/api/zabbixagent/settings/toggleAlias/',
            options: {
                rowCount:[10,25,50,100,500,1000]
            }
        }
    );

    /***********************************************************************
     * Commands
     **********************************************************************/

    // form save event handlers for all defined forms
    $('[id*="save_"]').each(function(){
        $(this).click(function(){
            var frm_id = $(this).closest("form").attr("id");
            var frm_title = $(this).closest("form").attr("data-title");

            // save data for tab
            saveFormToEndpoint(url="/api/zabbixagent/settings/set",formid=frm_id,callback_ok=function(){
                // set progress animation when reloading
                $("#"+frm_id+"_progress").addClass("fa fa-spinner fa-pulse");

                // on correct save, perform restart
                ajaxCall(url="/api/zabbixagent/service/reconfigure", sendData={}, callback=function(data,status){
                    // when done, disable progress animation.
                    $("#"+frm_id+"_progress").removeClass("fa fa-spinner fa-pulse");

                    if (status != "success" || data['status'] != 'ok' ) {
                        // fix error handling
                        BootstrapDialog.show({
                            type:BootstrapDialog.TYPE_WARNING,
                            title: frm_title,
                            message: JSON.stringify(data),
                            draggable: true
                        });
                    } else {
                        updateServiceControlUI('zabbixagent');
                    }
                    // when done, disable progress animation.
                    $("#"+frm_id+"_progress").removeClass("fa fa-spinner fa-pulse");
                });
            });
        });
    });

    // Reconfigure - activate changes
    $('[id*="reconfigureAct"]').each(function(){
        $(this).click(function(){
            // set progress animation
            $('[id*="reconfigureAct_progress"]').each(function(){
                $(this).addClass("fa fa-spinner fa-pulse");
            });
            // reconfigure service
            ajaxCall(url="/api/zabbixagent/service/reconfigure", sendData={}, callback=function(data,status) {
                if (status != "success" || data['status'] != 'ok') {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_WARNING,
                        title: "<?= $lang->_('Error reconfiguring Zabbix Agent') ?>",
                        message: data['status'],
                        draggable: true
                    });
                }
                // when done, disable progress animation
                $('[id*="reconfigureAct_progress"]').each(function(){
                    $(this).removeClass("fa fa-spinner fa-pulse");
                });
            });
        });
    });

    // update history on tab state and implement navigation
    if(window.location.hash != "") {
        $('a[href="' + window.location.hash + '"]').click()
    }
    $('.nav-tabs a').on('shown.bs.tab', function (e) {
        history.pushState(null, null, e.target.hash);
    });
});
</script>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <?= $this->partial('layout_partials/base_tabs_header', ['formData' => $settingsForm]) ?>

    
    <li role="presentation" class="dropdown">
        <a data-toggle="dropdown" href="#" class="dropdown-toggle pull-right visible-lg-inline-block visible-md-inline-block visible-xs-inline-block visible-sm-inline-block" role="button">
            <b><span class="caret"></span></b>
        </a>
        <a data-toggle="tab" onclick="$('#userparameters-tab').click();" class="visible-lg-inline-block visible-md-inline-block visible-xs-inline-block visible-sm-inline-block" style="border-right:0px;"><b><?= $lang->_('Advanced') ?></b></a>
        <ul class="dropdown-menu" role="menu">
            <li><a data-toggle="tab" id="userparameters-tab" href="#userparameters"><?= $lang->_('User Parameters') ?></a></li>
            <li><a data-toggle="tab" id="aliases-tab" href="#aliases"><?= $lang->_('Item Key Aliases') ?></a></li>
        </ul>
    </li>
</ul>

<div class="content-box tab-content">
    
    <?= $this->partial('layout_partials/base_tabs_content', ['formData' => $settingsForm]) ?>

    
    <div id="userparameters" class="tab-pane fade">
        <!-- tab page "userparameters" -->
        <table id="grid-userparameters" class="table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogUserparameter">
            <thead>
            <tr>
                <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle"><?= $lang->_('Enabled') ?></th>
                <th data-column-id="key" data-type="string"><?= $lang->_('User Parameter Key') ?></th>
                <th data-column-id="command" data-type="string"><?= $lang->_('User Parameter Command') ?></th>
                <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false"><?= $lang->_('Commands') ?></th>
                <th data-column-id="uuid" data-type="string" data-identifier="true"  data-visible="false"><?= $lang->_('ID') ?></th>
            </tr>
            </thead>
            <tbody>
            </tbody>
            <tfoot>
            <tr>
                <td></td>
                <td>
                    <button data-action="add" type="button" class="btn btn-xs btn-default"><span class="fa fa-plus"></span></button>
                    <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-trash-o"></span></button>
                </td>
            </tr>
            </tfoot>
        </table>
        <!-- apply button -->
        <div class="col-md-12">
            <hr/>
            <button class="btn btn-primary" id="reconfigureAct-userparameters" type="button"><b><?= $lang->_('Apply') ?></b><i id="reconfigureAct_progress" class=""></i></button>
            <br/>
            <br/>
        </div>
    </div>
    <div id="aliases" class="tab-pane fade">
        <!-- tab page "aliases" -->
        <table id="grid-aliases" class="table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogAlias">
            <thead>
            <tr>
                <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle"><?= $lang->_('Enabled') ?></th>
                <th data-column-id="key" data-type="string"><?= $lang->_('Alias Key') ?></th>
                <th data-column-id="sourceKey" data-type="string"><?= $lang->_('Alias Source Key') ?></th>
                <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false"><?= $lang->_('Commands') ?></th>
                <th data-column-id="uuid" data-type="string" data-identifier="true"  data-visible="false"><?= $lang->_('ID') ?></th>
            </tr>
            </thead>
            <tbody>
            </tbody>
            <tfoot>
            <tr>
                <td></td>
                <td>
                    <button data-action="add" type="button" class="btn btn-xs btn-default"><span class="fa fa-plus"></span></button>
                    <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-trash-o"></span></button>
                </td>
            </tr>
            </tfoot>
        </table>
        <!-- apply button -->
        <div class="col-md-12">
            <hr/>
            <button class="btn btn-primary" id="reconfigureAct-aliases" type="button"><b><?= $lang->_('Apply') ?></b><i id="reconfigureAct_progress" class=""></i></button>
            <br/>
            <br/>
        </div>
    </div>
</div>


<?= $this->partial('layout_partials/base_dialog', ['fields' => $formDialogUserparameter, 'id' => 'DialogUserparameter', 'label' => $lang->_('Edit User Parameter')]) ?>
<?= $this->partial('layout_partials/base_dialog', ['fields' => $formDialogAlias, 'id' => 'DialogAlias', 'label' => $lang->_('Edit Alias')]) ?>
