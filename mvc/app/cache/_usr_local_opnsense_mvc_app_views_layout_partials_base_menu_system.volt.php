<aside id="navigation" class="page-side col-xs-12 col-sm-3 col-lg-2 hidden-xs">
    <div class="row">
        <nav class="page-side-nav">
            <div id="mainmenu" class="panel" style="border:0px">
                <div class="panel list-group" style="border:0px">
                    <?php foreach ($menuSystem as $topMenuItem) { ?>
                        <?php if ($this->length($topMenuItem->Children) >= 1) { ?>
                            <a href="#<?= $topMenuItem->Id ?>" class="list-group-item <?php if ($topMenuItem->Selected) { ?>  active-menu-title <?php } ?>" data-toggle="collapse" data-parent="#mainmenu">
                                <span class="<?= $topMenuItem->CssClass ?> __iconspacer"></span><?= $lang->_($topMenuItem->VisibleName) ?>
                            </a>
                            <div class="collapse  <?php if ($topMenuItem->Selected) { ?> active-menu in <?php } ?>" id="<?= $topMenuItem->Id ?>">
                                <?php foreach ($topMenuItem->Children as $subMenuItem) { ?>
                                    <?php if ($subMenuItem->Url == '') { ?>
                                    
                                        <a href="#<?= $topMenuItem->Id ?>_<?= $subMenuItem->Id ?>" class="list-group-item <?php if ($subMenuItem->Selected) { ?>  active-menu-title <?php } ?>"
                                            data-toggle="collapse" data-parent="#<?= $topMenuItem->Id ?>">
                                            <div style="display: table;width: 100%;">
                                                <div style="display: table-row">
                                                    <div style="display: table-cell"><?= $lang->_($subMenuItem->VisibleName) ?></div>
                                                    <div style="display: table-cell; text-align:right; vertical-align:middle;">
                                                        <span class="<?= $subMenuItem->CssClass ?>"></span>
                                                    </div>
                                                </div>
                                            </div>
                                        </a>
                                        <div class="collapse <?php if ($subMenuItem->Selected) { ?> active-menu in <?php } ?>" id="<?= $topMenuItem->Id ?>_<?= $subMenuItem->Id ?>">
                                            <?php foreach ($subMenuItem->Children as $subsubMenuItem) { ?> <?php if ($subsubMenuItem->IsExternal == 'Y') { ?>
                                            <a href="<?= $subsubMenuItem->Url ?>" target="_blank" rel="noopener noreferrer" class="list-group-item menu-level-3-item <?php if ($subsubMenuItem->Selected) { ?> active <?php } ?>"><?= $lang->_($subsubMenuItem->VisibleName) ?></a>
                                            <?php } elseif ($acl->isPageAccessible($this->session->get('Username'), $subsubMenuItem->Url)) { ?>
                                            <a href="<?= $subsubMenuItem->Url ?>" class="list-group-item menu-level-3-item <?php if ($subsubMenuItem->Selected) { ?> active <?php } ?>"><?= $lang->_($subsubMenuItem->VisibleName) ?></a>
                                            <?php } ?> <?php } ?>
                                        </div>
                                    <?php } elseif ($subMenuItem->IsExternal == 'Y') { ?>
                                        <a href="<?= $subMenuItem->Url ?>" target="_blank" rel="noopener noreferrer" class="list-group-item <?php if ($subMenuItem->Selected) { ?> active <?php } ?>"
                                            aria-expanded="<?php if ($subMenuItem->Selected) { ?>true<?php } else { ?>false<?php } ?>">
                                            <div style="display: table;width: 100%;">
                                                <div style="display: table-row">
                                                    <div style="display: table-cell"><?= $lang->_($subMenuItem->VisibleName) ?></div>
                                                    <div style="display: table-cell; text-align:right; vertical-align:middle;">
                                                        <span class="<?= $subMenuItem->CssClass ?>"></span>
                                                    </div>
                                                </div>
                                            </div>
                                        </a>
                                    <?php } elseif ($acl->isPageAccessible($this->session->get('Username'), $subMenuItem->Url)) { ?>
                                        <a href="<?= $subMenuItem->Url ?>" class="list-group-item <?php if ($subMenuItem->Selected) { ?> active <?php } ?>">
                                            <div style="display: table;width: 100%;">
                                                <div style="display: table-row">
                                                    <div style="display: table-cell"><?= $lang->_($subMenuItem->VisibleName) ?></div>
                                                    <div style="display: table-cell; text-align:right; vertical-align:middle;">
                                                        <span class="<?= $subMenuItem->CssClass ?>"></span>
                                                    </div>
                                                </div>
                                            </div>
                                        </a>
                                    <?php } ?>
                                <?php } ?>
                            </div>
                        <?php } else { ?>
                            
                            <?php if ($topMenuItem->IsExternal == 'Y') { ?>
                                <a href="<?= $topMenuItem->Url ?>" target="_blank" rel="noopener noreferrer" class="list-group-item <?php if ($topMenuItem->Selected) { ?>  active-menu-title <?php } ?>" data-parent="#mainmenu">
                                    <span class="<?= $topMenuItem->CssClass ?> __iconspacer"></span><?= $lang->_($topMenuItem->VisibleName) ?>
                                </a>
                            <?php } elseif ($acl->isPageAccessible($this->session->get('Username'), $topMenuItem->Url)) { ?>
                                <a href="<?= $topMenuItem->Url ?>" class="list-group-item <?php if ($topMenuItem->Selected) { ?>  active-menu-title <?php } ?>" data-parent="#mainmenu">
                                    <span class="<?= $topMenuItem->CssClass ?> __iconspacer"></span><?= $lang->_($topMenuItem->VisibleName) ?>
                                </a>
                            <?php } ?>
                        <?php } ?>
                    <?php } ?>
                </div>
            </div>
        </nav>
    </div>
</aside>
