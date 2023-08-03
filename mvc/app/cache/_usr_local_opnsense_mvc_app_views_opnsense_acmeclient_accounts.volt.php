

<script>

    $( document ).ready(function() {

        /***********************************************************************
         * link grid actions
         **********************************************************************/

        var gridParams = {
            search:'/api/acmeclient/accounts/search',
            get:'/api/acmeclient/accounts/get/',
            set:'/api/acmeclient/accounts/update/',
            add:'/api/acmeclient/accounts/add/',
            del:'/api/acmeclient/accounts/del/',
            toggle:'/api/acmeclient/accounts/toggle/',
            register:'/api/acmeclient/accounts/register/',
        };

        var gridopt = {
            ajax: true,
            selection: true,
            multiSelect: true,
            rowCount:[10,25,50,100,500,1000],
            url: '/api/acmeclient/accounts/search',
            formatters: {
                "commands": function (column, row) {
                    return "<button type=\"button\" title=\"<?= $lang->_('Edit account') ?>\" class=\"btn btn-xs btn-default command-edit bootgrid-tooltip\" data-row-id=\"" + row.uuid + "\"><span class=\"fa fa-pencil\"></span></button> " +
                        "<button type=\"button\" title=\"<?= $lang->_('Copy account') ?>\" class=\"btn btn-xs btn-default command-copy bootgrid-tooltip\" data-row-id=\"" + row.uuid + "\"><span class=\"fa fa-clone\"></span></button>" +
                        "<button type=\"button\" title=\"<?= $lang->_('Register account') ?>\" class=\"btn btn-xs btn-default command-register bootgrid-tooltip\" data-row-id=\"" + row.uuid + "\"><span class=\"fa fa-address-book-o\"></span></button>" +
                        "<button type=\"button\" title=\"<?= $lang->_('Remove account') ?>\" class=\"btn btn-xs btn-default command-delete bootgrid-tooltip\" data-row-id=\"" + row.uuid + "\"><span class=\"fa fa-trash-o\"></span></button>";
                },
                "rowtoggle": function (column, row) {
                    if (parseInt(row[column.id], 2) == 1) {
                        return "<span style=\"cursor: pointer;\" class=\"fa fa-check-square-o command-toggle\" data-value=\"1\" data-row-id=\"" + row.uuid + "\"></span>";
                    } else {
                        return "<span style=\"cursor: pointer;\" class=\"fa fa-square-o command-toggle\" data-value=\"0\" data-row-id=\"" + row.uuid + "\"></span>";
                    }
                },
                "accountstatus": function (column, row) {
                    if (row.statusCode == "" || row.statusCode == undefined) {
                        // fallback to lastUpdate value (unset if account was not registered)
                        if (row.statusLastUpdate == "" || row.statusLastUpdate == undefined) {
                            return "<?= $lang->_('not registered') ?>";
                        } else {
                            return "<?= $lang->_('OK') ?>";
                        }
                    } else if (row.statusCode == "100") {
                        return "<?= $lang->_('not registered') ?>";
                    } else if (row.statusCode == "200") {
                        return "<?= $lang->_('OK (registered)') ?>";
                    } else if (row.statusCode == "250") {
                        return "<?= $lang->_('deactivated') ?>";
                    } else if (row.statusCode == "300") {
                        return "<?= $lang->_('configuration error') ?>";
                    } else if (row.statusCode == "400") {
                        return "<?= $lang->_('registration failed') ?>";
                    } else if (row.statusCode == "500") {
                        return "<?= $lang->_('internal error') ?>";
                    } else {
                        return "<?= $lang->_('unknown') ?>";
                    }
                },
                "acmestatusdate": function (column, row) {
                    if (row.statusLastUpdate == "" || row.statusCode == undefined) {
                        return "<?= $lang->_('unknown') ?>";
                    } else {
                        var statusdate = new Date(row.statusLastUpdate*1000);
                        return statusdate.toLocaleString();
                    }
                }
            },
        };

        /**
         * reload bootgrid, return to current selected page
         */
        function std_bootgrid_reload(gridId) {
            var currentpage = $("#"+gridId).bootgrid("getCurrentPage");
            $("#"+gridId).bootgrid("reload");
            // absolutely not perfect, bootgrid.reload doesn't seem to support when().done()
            setTimeout(function(){
                $('#'+gridId+'-footer  a[data-page="'+currentpage+'"]').click();
            }, 400);
        }

        /**
         * copy actions for selected items from opnsense_bootgrid_plugin.js
         */
        var grid_accounts = $("#grid-accounts").bootgrid(gridopt).on("loaded.rs.jquery.bootgrid", function (e)
        {
            // toggle all rendered tooltips (once for all)
            $('.bootgrid-tooltip').tooltip();

            // scale footer on resize
            $(this).find("tfoot td:first-child").attr('colspan',$(this).find("th").length - 1);
            $(this).find('tr[data-row-id]').each(function(){
                if ($(this).find('[class*="command-toggle"]').first().data("value") == "0") {
                    $(this).addClass("text-muted");
                }
            });

            // edit dialog id to use
            var editDlg = $(this).attr('data-editDialog');
            var gridId = $(this).attr('id');

            // link Add new to child button with data-action = add
            $(this).find("*[data-action=add]").click(function(){
                if ( gridParams['get'] != undefined && gridParams['add'] != undefined) {
                    var urlMap = {};
                    urlMap['frm_' + editDlg] = gridParams['get'];
                    mapDataToFormUI(urlMap).done(function(){
                        // update selectors
                        formatTokenizersUI();
                        $('.selectpicker').selectpicker('refresh');
                        // clear validation errors (if any)
                        clearFormValidation('frm_' + editDlg);
                    });

                    // show dialog for edit
                    $('#'+editDlg).modal({backdrop: 'static', keyboard: false});
                    //
                    $("#btn_"+editDlg+"_save").unbind('click').click(function(){
                        saveFormToEndpoint(url=gridParams['add'],
                            formid='frm_' + editDlg, callback_ok=function(){
                                $("#"+editDlg).modal('hide');
                                $("#"+gridId).bootgrid("reload");
                            }, true);
                    });
                }  else {
                    console.log("[grid] action add missing")
                }
            });

            // link delete selected items action
            $(this).find("*[data-action=deleteSelected]").click(function(){
                if ( gridParams['del'] != undefined) {
                    stdDialogConfirm('<?= $lang->_('Confirm removal') ?>',
                        '<?= $lang->_('Do you want to remove the selected item?') ?>',
                        '<?= $lang->_('Yes') ?>', '<?= $lang->_('Cancel') ?>', function () {
                        var rows =$("#"+gridId).bootgrid('getSelectedRows');
                        if (rows != undefined){
                            var deferreds = [];
                            $.each(rows, function(key,uuid){
                                deferreds.push(ajaxCall(url=gridParams['del'] + uuid, sendData={},null));
                            });
                            // refresh after load
                            $.when.apply(null, deferreds).done(function(){
                                std_bootgrid_reload(gridId);
                            });
                        }
                    });
                } else {
                    console.log("[grid] action del missing")
                }
            });

        });

        /**
         * copy actions for items from opnsense_bootgrid_plugin.js
         */
        grid_accounts.on("loaded.rs.jquery.bootgrid", function(){

            // edit dialog id to use
            var editDlg = $(this).attr('data-editDialog');
            var gridId = $(this).attr('id');

            // edit item
            grid_accounts.find(".command-edit").on("click", function(e)
            {
                if (editDlg != undefined && gridParams['get'] != undefined) {
                    var uuid = $(this).data("row-id");
                    var urlMap = {};
                    urlMap['frm_' + editDlg] = gridParams['get'] + uuid;
                    mapDataToFormUI(urlMap).done(function () {
                        // update selectors
                        formatTokenizersUI();
                        $('.selectpicker').selectpicker('refresh');
                        // clear validation errors (if any)
                        clearFormValidation('frm_' + editDlg);
                    });

                    // show dialog for pipe edit
                    $('#'+editDlg).modal({backdrop: 'static', keyboard: false});
                    // define save action
                    $("#btn_"+editDlg+"_save").unbind('click').click(function(){
                        if (gridParams['set'] != undefined) {
                            saveFormToEndpoint(url=gridParams['set']+uuid,
                                formid='frm_' + editDlg, callback_ok=function(){
                                    $("#"+editDlg).modal('hide');
                                    std_bootgrid_reload(gridId);
                                }, true);
                        } else {
                            console.log("[grid] action set missing")
                        }
                    });
                } else {
                    console.log("[grid] action get or data-editDialog missing")
                }
            });

            // copy item, save as new
            grid_accounts.find(".command-copy").on("click", function(e)
            {
                if (editDlg != undefined && gridParams['get'] != undefined) {
                    var uuid = $(this).data("row-id");
                    var urlMap = {};
                    urlMap['frm_' + editDlg] = gridParams['get'] + uuid;
                    mapDataToFormUI(urlMap).done(function () {
                        // update selectors
                        formatTokenizersUI();
                        $('.selectpicker').selectpicker('refresh');
                        // clear validation errors (if any)
                        clearFormValidation('frm_' + editDlg);
                    });

                    // show dialog for pipe edit
                    $('#'+editDlg).modal({backdrop: 'static', keyboard: false});
                    // define save action
                    $("#btn_"+editDlg+"_save").unbind('click').click(function(){
                        if (gridParams['add'] != undefined) {
                            saveFormToEndpoint(url=gridParams['add'],
                                formid='frm_' + editDlg, callback_ok=function(){
                                    $("#"+editDlg).modal('hide');
                                    std_bootgrid_reload(gridId);
                                }, true);
                        } else {
                            console.log("[grid] action add missing")
                        }
                    });
                } else {
                    console.log("[grid] action get or data-editDialog missing")
                }
            });

            // delete item
            grid_accounts.find(".command-delete").on("click", function(e)
            {
                if (gridParams['del'] != undefined) {
                    var uuid=$(this).data("row-id");
                    stdDialogConfirm('<?= $lang->_('Confirm removal') ?>',
                        '<?= $lang->_('Do you want to remove the selected item?') ?>',
                        '<?= $lang->_('Yes') ?>', '<?= $lang->_('Cancel') ?>', function () {
                        ajaxCall(url=gridParams['del'] + uuid,
                            sendData={},callback=function(data,status){
                                // reload grid after delete
                                $("#"+gridId).bootgrid("reload");
                            });
                    });
                } else {
                    console.log("[grid] action del missing")
                }
            });

            // toggle item
            grid_accounts.find(".command-toggle").on("click", function(e)
            {
                if (gridParams['toggle'] != undefined) {
                    var uuid=$(this).data("row-id");
                    $(this).addClass("fa-spinner fa-pulse");
                    ajaxCall(url=gridParams['toggle'] + uuid,
                        sendData={},callback=function(data,status){
                            // reload grid after toggle
                            std_bootgrid_reload(gridId);
                        });
                } else {
                    console.log("[grid] action toggle missing")
                }
            });

            // register account
            grid_accounts.find(".command-register").on("click", function(e)
            {
                if (gridParams['register'] != undefined) {
                    var uuid=$(this).data("row-id");
                    stdDialogConfirm('<?= $lang->_('Confirmation Required') ?>',
                        '<?= $lang->_('Register the selected account with the configured ACME CA?') ?>',
                        '<?= $lang->_('Yes') ?>', '<?= $lang->_('Cancel') ?>', function() {
                        ajaxCall(url=gridParams['register'] + uuid,sendData={},callback=function(data,status){
                            // reload grid afterwards
                            $("#"+gridId).bootgrid("reload");
                        });
                    });
                } else {
                    console.log("[grid] action register missing")
                }
            });

        });

        // hook into on-show event for dialog to extend layout.
        $('#DialogAccount').on('shown.bs.modal', function (e) {
            // hide options that are irrelevant for the selected CA
            $("#account\\.ca").change(function(){
                $(".ca_options").hide();
                $(".ca_options_"+$(this).val()).show();
            });
            $("#account\\.ca").change();
        })

    });

</script>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li <?php if ((empty($showIntro) ? ('0') : ($showIntro)) == '1') { ?>class="active"<?php } ?>><a data-toggle="tab" id="accounts-introduction" href="#subtab_accounts-introduction"><b><?= $lang->_('Introduction') ?></b></a></li>
    <li <?php if ((empty($showIntro) ? ('0') : ($showIntro)) == '0') { ?>class="active"<?php } ?>><a data-toggle="tab" id="accounts-tab" href="#accounts"><b><?= $lang->_('Accounts') ?></b></a></li>
</ul>

<div class="content-box tab-content">

    <div id="subtab_accounts-introduction" class="tab-pane fade <?php if ((empty($showIntro) ? ('0') : ($showIntro)) == '1') { ?>in active<?php } ?>">
        <div class="col-md-12">
            <h1><?= $lang->_('Accounts') ?></h1>
            <p><?= $lang->_('In order to create certificates, an account is required. Also the following information should be considered:') ?></p>
            <ul>
              <li><?= sprintf($lang->_('The account will be %sregistered automatically%s at the chosen CA. The CA will then associate new certificates to the selected account.'), '<b>', '</b>') ?></li>
              <li><?= sprintf($lang->_('Usually CAs will let you know if something went wrong and a certificate is about to expire, therefore a %svalid e-mail address%s should be provided.'), '<b>', '</b>') ?></li>
              <li><?= sprintf($lang->_('For certain use-cases it can be useful to register %smultiple accounts%s, but the policy of the CA should be respected with this regard.'), '<b>', '</b>') ?></li>
            </ul>
            <p><?= sprintf($lang->_('When requesting support from a CA the account ID may be required, %sthis documentation%s contains information how to get the internal account ID from the log files.'), '<a href="https://letsencrypt.org/docs/account-id/">', '</a>') ?></p>
        </div>
    </div>

    <div id="accounts" class="tab-pane fade <?php if ((empty($showIntro) ? ('0') : ($showIntro)) == '0') { ?>in active<?php } ?>">

        <table id="grid-accounts" class="table table-condensed table-hover table-striped table-responsive" data-editDialog="DialogAccount">
            <thead>
            <tr>
                <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle"><?= $lang->_('Enabled') ?></th>
                <th data-column-id="name" data-type="string"><?= $lang->_('Name') ?></th>
                <th data-column-id="email" data-type="string"><?= $lang->_('E-Mail') ?></th>
                <th data-column-id="ca" data-type="string"><?= $lang->_('CA') ?></th>
                <th data-column-id="statusCode" data-type="string" data-formatter="accountstatus"><?= $lang->_('Status') ?></th>
                <th data-column-id="statusLastUpdate" data-type="string" data-formatter="acmestatusdate"><?= $lang->_('Registration Date') ?></th>
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

    </div>

</div>


<?= $this->partial('layout_partials/base_dialog', ['fields' => $formDialogAccount, 'id' => 'DialogAccount', 'label' => $lang->_('Edit Account')]) ?>
