

<?php foreach ((empty($formData['tabs']) ? ([]) : ($formData['tabs'])) as $tab) { ?>
    <?php if ((empty($tab['subtabs']) ? (false) : ($tab['subtabs']))) { ?>
        
        
            <?php $active_subtab = ''; ?>
            <?php foreach ((empty($tab['subtabs']) ? ([]) : ($tab['subtabs'])) as $subtab) { ?>
                <?php if ($subtab[0] == (empty($formData['activetab']) ? ('') : ($formData['activetab']))) { ?>
                    <?php $active_subtab = $subtab[0]; ?>
                <?php } ?>
            <?php } ?>

        <li role="presentation" class="dropdown <?php if ((empty($formData['activetab']) ? ('') : ($formData['activetab'])) == $active_subtab) { ?>active<?php } ?>">
            <a data-toggle="dropdown" href="#" class="dropdown-toggle pull-right visible-lg-inline-block visible-md-inline-block visible-xs-inline-block visible-sm-inline-block" role="button">
                <b><span class="caret"></span></b>
            </a>
            <a data-toggle="tab" onclick="$('#subtab_item_<?= $tab['subtabs'][0][0] ?>').click();" class="visible-lg-inline-block visible-md-inline-block visible-xs-inline-block visible-sm-inline-block" style="border-right:0px;"><b><?= $tab[1] ?></b></a>
            <ul class="dropdown-menu" role="menu">
                <?php foreach ((empty($tab['subtabs']) ? ([]) : ($tab['subtabs'])) as $subtab) { ?>
                <li class="<?php if ((empty($formData['activetab']) ? ('') : ($formData['activetab'])) == $subtab[0]) { ?>active<?php } ?>">
                    <a data-toggle="tab" id="subtab_item_<?= $subtab[0] ?>" href="#subtab_<?= $subtab[0] ?>"><?= $subtab[1] ?></a>
                </li>
                <?php } ?>
            </ul>
        </li>
    <?php } else { ?>
        
        <li <?php if ((empty($formData['activetab']) ? ('') : ($formData['activetab'])) == $tab[0]) { ?> class="active" <?php } ?>>
                <a data-toggle="tab" href="#tab_<?= $tab[0] ?>">
                    <b><?= $tab[1] ?></b>
                </a>
        </li>
    <?php } ?>
<?php } ?>
