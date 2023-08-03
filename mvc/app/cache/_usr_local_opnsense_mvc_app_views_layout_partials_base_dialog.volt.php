




<?php $base_dialog_id = $id; ?>
<?php $base_dialog_fields = $fields; ?>
<?php $base_dialog_label = $label; ?>


<?php $base_dialog_help = false; ?>
<?php $base_dialog_advanced = false; ?>
<?php foreach ((empty($base_dialog_fields) ? ([]) : ($base_dialog_fields)) as $field) { ?>
    <?php foreach ($field as $name => $element) { ?>
        <?php if ($name == 'help') { ?>
            <?php $base_dialog_help = true; ?>
        <?php } ?>
        <?php if ($name == 'advanced') { ?>
            <?php $base_dialog_advanced = true; ?>
        <?php } ?>
    <?php } ?>
    <?php if ((empty($base_dialog_help) ? (false) : ($base_dialog_help)) && (empty($base_dialog_advanced) ? (false) : ($base_dialog_advanced))) { ?>
        <?php break; ?>
    <?php } ?>
<?php } ?>

<div class="modal fade" id="<?= $base_dialog_id ?>" tabindex="-1" role="dialog" aria-labelledby="<?= $base_dialog_id ?>Label" aria-hidden="true">
    <div class="modal-backdrop fade in"></div>
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="<?= $lang->_('Close') ?>"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="<?= $base_dialog_id ?>Label"><?= $base_dialog_label ?></h4>
            </div>
            <div class="modal-body">
                <form id="frm_<?= $base_dialog_id ?>">
                  <div class="table-responsive">
                    <table class="table table-striped table-condensed">
                        <colgroup>
                            <col class="col-md-3"/>
                            <col class="col-md-<?= 12 - 3 - (empty($msgzone_width) ? (5) : ($msgzone_width)) ?>"/>
                            <col class="col-md-<?= (empty($msgzone_width) ? (5) : ($msgzone_width)) ?>"/>
                        </colgroup>
                        <tbody>
                        <?php if ((empty($base_dialog_advanced) ? (false) : ($base_dialog_advanced)) || (empty($base_dialog_help) ? (false) : ($base_dialog_help))) { ?>
                        <tr>
                            <td><?php if ((empty($base_dialog_advanced) ? (false) : ($base_dialog_advanced))) { ?><a href="#"><i class="fa fa-toggle-off text-danger" id="show_advanced_formDialog<?= $base_dialog_id ?>"></i></a> <small><?= $lang->_('advanced mode') ?></small><?php } ?></td>
                            <td colspan="2" style="text-align:right;">
                                <?php if ((empty($base_dialog_help) ? (false) : ($base_dialog_help))) { ?><small><?= $lang->_('full help') ?></small> <a href="#"><i class="fa fa-toggle-off text-danger" id="show_all_help_formDialog<?= $base_dialog_id ?>"></i></a><?php } ?>
                            </td>
                        </tr>
                        <?php } ?>
                        <?php foreach ((empty($base_dialog_fields) ? ([]) : ($base_dialog_fields)) as $field) { ?>
                            
                            <?php $advanced = false; ?>
                            <?php $help = false; ?>
                            <?php $hint = false; ?>
                            <?php $style = false; ?>
                            <?php $maxheight = false; ?>
                            <?php $width = false; ?>
                            <?php $allownew = false; ?>
                            <?php $readonly = false; ?>
                            <?php if ($field['type'] == 'header') { ?>
                              


      </tbody>
    </table>
  </div>
  <div class="table-responsive <?= (empty($field['style']) ? ('') : ($field['style'])) ?>">
    <table class="table table-striped table-condensed">
        <colgroup>
            <col class="col-md-3"/>
            <col class="col-md-<?= 12 - 3 - (empty($msgzone_width) ? (5) : ($msgzone_width)) ?>"/>
            <col class="col-md-<?= (empty($msgzone_width) ? (5) : ($msgzone_width)) ?>"/>
        </colgroup>
        <thead>
          <tr<?php if ((empty($field['advanced']) ? (false) : ($field['advanced'])) == 'true') { ?> data-advanced="true"<?php } ?>>
            <th colspan="3"><h2><?= $field['label'] ?></h2></th>
          </tr>
        </thead>
        <tbody>


                            <?php } else { ?>
                              <?= $this->partial('layout_partials/form_input_tr', $field) ?>
                            <?php } ?>
                        <?php } ?>
                        </tbody>
                    </table>
                  </div>
                </form>
            </div>
            <div class="modal-footer">
                <?php if ((empty($hasSaveBtn) ? ('true') : ($hasSaveBtn)) == 'true') { ?>
                <button type="button" class="btn btn-default" data-dismiss="modal"><?= $lang->_('Cancel') ?></button>
                <button type="button" class="btn btn-primary" id="btn_<?= $base_dialog_id ?>_save"><?= $lang->_('Save') ?> <i id="btn_<?= $base_dialog_id ?>_save_progress" class=""></i></button>
                <?php } else { ?>
                <button type="button" class="btn btn-default" data-dismiss="modal"><?= $lang->_('Close') ?></button>
                <?php } ?>
            </div>
        </div>
    </div>
</div>
