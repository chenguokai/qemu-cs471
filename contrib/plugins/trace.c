#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>


#include <qemu-plugin.h>
//#include <plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb* tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;
    for (i = 0; i < n; i++) {
        uint64_t *cnt;
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        printf("tid %u va %lx\n", gettid(), qemu_plugin_insn_vaddr(insn));
    }
}

static void plugin_init(void)
{}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    int i;

    if (strcmp(info->target_name, "aarch64") != 0)
        return -1;

    //plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    // qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}