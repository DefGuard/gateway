

<tr id="row_<?= $id ?>" <?php if ((empty($advanced) ? (false) : ($advanced)) == 'true') { ?> data-advanced="true"<?php } ?>>
    <td>
        <div class="control-label" id="control_label_<?= $id ?>">
            <?php if ((empty($help) ? (false) : ($help))) { ?>
                <a id="help_for_<?= $id ?>" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a>
            <?php } elseif ((empty($help) ? (false) : ($help)) == false) { ?>
                <i class="fa fa-info-circle text-muted"></i>
            <?php } ?>
            <b><?= $label ?></b>
        </div>
    </td>
    <td>
        <?php if ($type == 'text') { ?>
            <input  type="text"
                    class="form-control <?= (empty($style) ? ('') : ($style)) ?>"
                    size="<?= (empty($size) ? ('50') : ($size)) ?>"
                    id="<?= $id ?>"
                    <?= ((empty($readonly) ? (false) : ($readonly)) ? 'readonly="readonly"' : '') ?>
                    <?php if ((empty($hint) ? (false) : ($hint))) { ?>placeholder="<?= $hint ?>"<?php } ?>
            >
        <?php } elseif ($type == 'hidden') { ?>
            <input type="hidden" id="<?= $id ?>" class="<?= (empty($style) ? ('') : ($style)) ?>" >
        <?php } elseif ($type == 'checkbox') { ?>
            <input type="checkbox"  class="<?= (empty($style) ? ('') : ($style)) ?>" id="<?= $id ?>">
        <?php } elseif ($this->isIncluded($type, ['select_multiple', 'dropdown'])) { ?>
            <select <?php if ($type == 'select_multiple') { ?>multiple="multiple"<?php } ?>
                    <?php if ((empty($size) ? (false) : ($size))) { ?>data-size="<?= $size ?>"<?php } ?>
                    id="<?= $id ?>"
                    class="<?= (empty($style) ? ('selectpicker') : ($style)) ?>"
                    <?php if ((empty($hint) ? (false) : ($hint))) { ?>data-hint="<?= $hint ?>"<?php } ?>
                    data-width="<?= (empty($width) ? ('334px') : ($width)) ?>"
                    data-allownew="<?= (empty($allownew) ? ('false') : ($allownew)) ?>"
                    data-sortable="<?= (empty($sortable) ? ('false') : ($sortable)) ?>"
                    data-live-search="true"
                    <?php if ((empty($separator) ? (false) : ($separator))) { ?>data-separator="<?= $separator ?>"<?php } ?>
            ></select>
            <?php if ($type == 'select_multiple') { ?>
              <?php if ((empty($style) ? ('selectpicker') : ($style)) != 'tokenize') { ?><br /><?php } ?>
              <a href="#" class="text-danger" id="clear-options_<?= $id ?>"><i class="fa fa-times-circle"></i> <small><?= $lang->_('Clear All') ?></small></a>
              <?php if ((empty($style) ? ('selectpicker') : ($style)) == 'tokenize') { ?>&nbsp;&nbsp;<a href="#" class="text-danger" id="copy-options_<?= $id ?>"><i class="fa fa-copy"></i> <small><?= $lang->_('Copy') ?></small></a>
              &nbsp;&nbsp;<a href="#" class="text-danger" id="paste-options_<?= $id ?>" style="display:none"><i class="fa fa-paste"></i> <small><?= $lang->_('Paste') ?></small></a>
              <?php } ?>
            <?php } ?>
        <?php } elseif ($type == 'password') { ?>
            <input type="password" autocomplete="new-password" class="form-control <?= (empty($style) ? ('') : ($style)) ?>" size="<?= (empty($size) ? ('50') : ($size)) ?>" id="<?= $id ?>" <?= ((empty($readonly) ? (false) : ($readonly)) ? 'readonly="readonly"' : '') ?> >
        <?php } elseif ($type == 'textbox') { ?>
            <textarea class="<?= (empty($style) ? ('') : ($style)) ?>" rows="<?= (empty($height) ? ('5') : ($height)) ?>" id="<?= $id ?>" <?= ((empty($readonly) ? (false) : ($readonly)) ? 'readonly="readonly"' : '') ?>></textarea>
        <?php } elseif ($type == 'info') { ?>
            <span  class="<?= (empty($style) ? ('') : ($style)) ?>" id="<?= $id ?>"></span>
        <?php } ?>
        <?php if ((empty($help) ? (false) : ($help))) { ?>
            <div class="hidden" data-for="help_for_<?= $id ?>">
                <small><?= $help ?></small>
            </div>
        <?php } ?>
    </td>
    <td>
        <span class="help-block" id="help_block_<?= $id ?>"></span>
    </td>
</tr>
