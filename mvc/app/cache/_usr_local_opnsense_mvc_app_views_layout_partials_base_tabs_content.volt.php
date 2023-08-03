

<?php foreach ((empty($formData['tabs']) ? ([]) : ($formData['tabs'])) as $tab) { ?>
    <?php if ((empty($tab['subtabs']) ? (false) : ($tab['subtabs']))) { ?>
        
        <?php foreach ((empty($tab['subtabs']) ? ([]) : ($tab['subtabs'])) as $subtab) { ?>
                <div id="subtab_<?= $subtab[0] ?>" class="tab-pane fade<?php if ((empty($formData['activetab']) ? ('') : ($formData['activetab'])) == $subtab[0]) { ?> in active <?php } ?>">
                    <?= $this->partial('layout_partials/base_form', ['fields' => $subtab[2], 'id' => 'frm_' . $subtab[0], 'data_title' => $subtab[1], 'apply_btn_id' => 'save_' . $subtab[0]]) ?>
                </div>
        <?php } ?>
    <?php } ?>
    <?php if ((empty($tab['subtabs']) ? (false) : ($tab['subtabs'])) == false) { ?>
            <div id="tab_<?= $tab[0] ?>" class="tab-pane fade<?php if ((empty($formData['activetab']) ? ('') : ($formData['activetab'])) == $tab[0]) { ?> in active <?php } ?>">
                <?= $this->partial('layout_partials/base_form', ['fields' => $tab[2], 'id' => 'frm_' . $tab[0], 'apply_btn_id' => 'save_' . $tab[0]]) ?>
            </div>
    <?php } ?>
<?php } ?>
