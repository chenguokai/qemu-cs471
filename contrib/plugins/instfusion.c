
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>


#include <qemu-plugin.h>

#include "riscv64insts.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef gpointer InstInfoHash;

static inline uint32_t bits(uint32_t val, uint8_t msb, uint8_t len)
{
    return (val << (31 - msb)) >> (32 - len);
}

static inline uint32_t decode32Rd(uint32_t inst)
{
    return bits(inst, 11, 5);
}

static inline uint32_t decode32Rs1(uint32_t inst)
{
    return bits(inst, 19, 5);
}

static inline uint32_t decode32Rs2(uint32_t inst)
{
    return bits(inst, 24, 5);
}

static inline uint32_t decode32Shamt(uint32_t inst)
{
    return bits(inst, 25, 6);
}

typedef struct InstInfo {
    InstPatternInfo* info;
    uint8_t rd;
    uint8_t rs1;
    uint8_t rs2;
    union {
        uint8_t shamt;
        uint8_t imm;
    };
    GHashTable* follow_insts_cnt;   // InstInfoHash -> counter;
} InstInfo;

static inline InstInfo* allocDefaultInstInfo(void)
{
    InstInfo* instInfo = g_new0(InstInfo, 1);
    instInfo->info  = NULL;
    instInfo->rd    = 0;
    instInfo->rs1   = 0;
    instInfo->rs2   = 0;
    instInfo->shamt = 0;
    return instInfo;
}

static inline InstInfo* initInstInfo(InstInfo* instInfo, InstPatternInfo* patternInfo, uint32_t inst)
{
    instInfo->info  = patternInfo;
    switch(instInfo->info->pattern_type) {
        case PT_CLD:
            instInfo->rd    = 0x8 | bits(inst, 4, 3);
            instInfo->rs1   = 0x8 | bits(inst, 9, 3);
            instInfo->rs2   = 0;
            instInfo->shamt = 0;
            break;
        case PT_CST:
            instInfo->rd    = 0;
            instInfo->rs1   = 0x8 | bits(inst, 9, 3);
            instInfo->rs2   = 0x8 | bits(inst, 4, 3);
            instInfo->shamt = 0;
            break;
        case PT_CIRD5: // c.addi, c.addiw, c.li, c.addi16sp, c.lui
            instInfo->rd    = bits(inst, 11, 5);
            instInfo->rs1   = bits(inst, 11, 5);
            instInfo->rs2   = 0;
            instInfo->shamt = 0;            
            break;
        case PT_CIRD3: // c.andi
            instInfo->rd    = 0x8 | bits(inst, 9, 3);
            instInfo->rs1   = 0x8 | bits(inst, 9, 3);
            instInfo->rs2   = 0;
            instInfo->imm   = bits(inst, 12, 1) | bits(inst, 6, 5);
            break;
        case PT_CSHRD3: // c.srli, c.srai
            instInfo->rd    = 0x8 | bits(inst, 9, 3);
            instInfo->rs1   = 0x8 | bits(inst, 9, 3);
            instInfo->rs2   = 0;
            instInfo->shamt = (bits(inst, 12, 1) << 5) | bits(inst, 6, 5);
            break;
        case PT_CSHRD5: // c.slli
            instInfo->rd    = bits(inst, 11, 5);
            instInfo->rs1   = bits(inst, 11, 5);
            instInfo->rs2   = 0;
            instInfo->shamt = (bits(inst, 12, 1) << 5) | bits(inst, 6, 5);
            break;
        case PT_CSH64RD3: // c.srli64, c.srai64
            instInfo->rd    = 0x8 | bits(inst, 9, 3);
            instInfo->rs1   = 0x8 | bits(inst, 9, 3);
            instInfo->rs2   = 0;
            instInfo->shamt = 64;
            break;
        case PT_CSH64RD5: // c.slli64
            instInfo->rd    = bits(inst, 11, 5);
            instInfo->rs1   = bits(inst, 11, 5);
            instInfo->rs2   = 0;
            instInfo->shamt = 64;
            break;
        case PT_CB: // c.beqz, c.bnez
            instInfo->rd    = 0;
            instInfo->rs1   = 0x8 | bits(inst, 9, 3);
            instInfo->rs2   = 0;
            instInfo->shamt = 0;
            break;
        case PT_CLDSP: // c.ldsp, c.fldsp, c.lwsp
            instInfo->rd    = bits(inst, 11, 5);
            instInfo->rs1   = 2; // sp = 2
            instInfo->rs2   = 0;
            instInfo->shamt = 0;
            break;
        case PT_CSTSP: // c.sdsp, c.fsdsp, c.swsp
            instInfo->rd    = 0;
            instInfo->rs1   = 2; // sp = 2
            instInfo->rs2   = bits(inst, 11, 5);
            instInfo->shamt = 0;
            break;
        case PT_CADD: // c.add
            instInfo->rd    = bits(inst, 11, 5);
            instInfo->rs1   = bits(inst, 11, 5);
            instInfo->rs2   = bits(inst, 6, 5);
            instInfo->shamt = 0;
            break;
        case PT_CMV: // c.mv
            instInfo->rd    = bits(inst, 11, 5);
            instInfo->rs1   = 0;
            instInfo->rs2   = bits(inst, 6, 5);
            instInfo->shamt = 0;
            break;
        case PT_CJR: // c.jr
            instInfo->rd    = 0;
            instInfo->rs1   = bits(inst, 11, 5);
            instInfo->rs2   = 0;
            instInfo->shamt = 0;
            break;
        case PT_CJALR: // c.jalr
            instInfo->rd    = 1; // x1 is target reg of c.jalr
            instInfo->rs1   = bits(inst, 11, 5);
            instInfo->rs2   = 0;
            instInfo->shamt = 0;
            break;
        case PT_NONE: // Dont care insts
            instInfo->rd    = 0;
            instInfo->rs1   = 0;
            instInfo->rs2   = 0;
            instInfo->shamt = 0;
            break;
        default: // 32bits inst
            instInfo->rd    = decode32Rd(inst);
            instInfo->rs1   = decode32Rs1(inst);
            instInfo->rs2   = decode32Rs2(inst);
            instInfo->shamt = decode32Shamt(inst);
            break;
    }
    instInfo->follow_insts_cnt = NULL;
    return instInfo;
}

static InstInfo* allocInstInfo(InstPatternInfo* patternInfo, uint32_t inst)
{
    InstInfo* instInfo = g_new0(InstInfo, 1);
    initInstInfo(instInfo, patternInfo, inst);
    return instInfo;
}


static void freeInstInfo(InstInfo* instInfo)
{
    if (instInfo->follow_insts_cnt)
        g_hash_table_destroy(instInfo->follow_insts_cnt);
    g_free(instInfo);
}

static InstInfoHash instInfoHash(InstInfo* instInfo)
{
    uint64_t res = 0;
    switch(instInfo->info->pattern_type) {
        case PT_R:
            res |= instInfo->rd;
            res |= instInfo->rs1 << 8u;
            res |= instInfo->rs2 << 16u;
            break;
        case PT_JAL:
            res |= instInfo->rd;
            break;
        case PT_B:
            res |= instInfo->rs1;
            res |= instInfo->rs2 << 8u;
            break;
        case PT_I:
            res |= instInfo->rd;
            res |= instInfo->rs1 << 8u;
            break;
        case PT_LD:
            res |= instInfo->rd;
            res |= instInfo->rs1 << 8u;
            break;
        case PT_ST:
            res |= instInfo->rs1;
            res |= instInfo->rs2 << 8u;
            break;
        case PT_SH6:
        case PT_SH5:
            res |= instInfo->rd;
            res |= instInfo->rs1 << 8u;
            res |= instInfo->rs2 << 16u;
            break;
        case PT_SHI6:
        case PT_SHI5:
            res |= instInfo->rd;
            res |= instInfo->rs1 << 8u;
            res |= instInfo->shamt << 16u;
            break;
        case PT_CLD: // c.fld, c.lw, c.ld
            res |= instInfo->rd;
            break;
        case PT_CST: // c.fsd, c.sw, c.sd
            res |= instInfo->rs1;
            break;
        case PT_CIRD5: // c.addi, c.addiw, c.li, c.addi16sp, c.lui
            res |= instInfo->rd;
            break;
        case PT_CIRD3: // c.andi
            res |= instInfo->rd;
            res |= instInfo->imm << 8u;
            break;
        case PT_CSHRD3: // c.srli, c.srai
            res |= instInfo->rd;
            res |= instInfo->shamt << 8u;
            break;
        case PT_CSHRD5: // c.slli
            res |= instInfo->rd;
            res |= instInfo->shamt << 8u;
            break;
        case PT_CB: // c.beqz, c.bnez
            res |= instInfo->rs1;
            break;
        case PT_CLDSP: // c.ldsp, c.fldsp, c.lwsp
        case PT_CSTSP: // c.sdsp, c.fsdsp, c.swsp
            res |= instInfo->rd;
            break;
        case PT_CADD: // c.add
        case PT_CMV:
            res |= instInfo->rd;
            res |= instInfo->rs2 << 8u;
            break;
        case PT_CJR: // c.jr
        case PT_CJALR: // c.jalr
            res |= instInfo->rs1;
            break;
        default: break;
    }
    res |= ((uint64_t)instInfo->info->idx) << 32u;
    return (gpointer)res;
}



static uint32_t unclassed_inst;
static GHashTable* instTable; // InstInfoHash -> InstInfo
static bool do_inline;
static InstInfo* lastInfo;

static void plugin_init(void)
{
    instTable = g_hash_table_new(NULL, g_direct_equal);
    for (size_t i=0; i < ARRAY_SIZE(riscv64_insns); i++) {
        riscv64_insns[i].idx = i;
    }
}

static void vcpu_insn_exec_before(unsigned int cpu_index, void *udata)
{
    uint64_t *count = (uint64_t *) udata;
    (*count)++;
}

static uint64_t *find_counter(struct qemu_plugin_insn *insn)
{
    InstInfo* thisInfo = NULL;
    InstInfoHash thisHash;
    uint32_t masked_bits;
    InstPatternInfo* entry;
    uint64_t* counter = NULL;
    /*
     * We only match the first 32 bits of the instruction which is
     * fine for most RISCs but a bit limiting for CISC architectures.
     * They would probably benefit from a more tailored plugin.
     * However we can fall back to individual instruction counting.
     */
    uint32_t inst = *((uint32_t *)qemu_plugin_insn_data(insn));

    for (size_t i = 0; i < ARRAY_SIZE(riscv64_insns); i++) {
        entry = &riscv64_insns[i];
        masked_bits = inst & entry->mask;
        if (masked_bits == entry->pattern){
            break;
        }
    }

    if (entry->mask == 0) {
        unclassed_inst = inst;
    }

    // find new inst, if not exists, create it
    thisInfo = allocInstInfo(entry, inst);
    thisHash = instInfoHash(thisInfo);
    InstInfo* tmpInfo = (InstInfo*) g_hash_table_lookup(instTable, thisHash);
    if (tmpInfo == NULL) {
        g_hash_table_insert(instTable, thisHash, thisInfo);
    } else {
        freeInstInfo(thisInfo);
        thisInfo = tmpInfo;
    }

    // if this is the first inst, neednot fusion counter
    // otherwise, find fusion counter
    if (lastInfo != NULL) {
        if (lastInfo->follow_insts_cnt != NULL) {
            counter = (uint64_t*) g_hash_table_lookup(lastInfo->follow_insts_cnt, thisHash);
        } else {
            lastInfo->follow_insts_cnt = g_hash_table_new(NULL, g_direct_equal);
        }
        if (counter == NULL) {
            counter = g_new0(uint64_t, 1);
            g_hash_table_insert(lastInfo->follow_insts_cnt, thisHash, (gpointer)counter);
        }
    }
    // static value hold this inst info as last inst info
    lastInfo = thisInfo;

    return counter;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb* tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;
    for (i = 0; i < n; i++) {
        uint64_t *cnt;
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        cnt = find_counter(insn);
        if (cnt) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, vcpu_insn_exec_before, QEMU_PLUGIN_CB_NO_REGS, cnt);
        }
    }
}

static void print_inst(InstInfo* info)
{
    g_autoptr(GString) report = g_string_new("");
    switch (info->info->pattern_type) {
        case PT_R:
        case PT_SH5:
        case PT_SH6:
        case PT_CADD: // c.add
        case PT_CMV: // c.mv
            g_string_append_printf(report, "%s$rd@%hhu,$rs1@%hhu,$rs2@%hhu",
                info->info->name,
                info->rd,
                info->rs1,
                info->rs2
            );
            break;
        case PT_JAL:
            g_string_append_printf(report, "%s$rd@%hhu",
                info->info->name,
                info->rd
            );
            break;
        case PT_B:
        case PT_CB: // c.beqz, c.bnez
        case PT_ST:
        case PT_CST:
        case PT_CSTSP:
            g_string_append_printf(report, "%s$rs1@%hhu,$rs2@%hhu",
                info->info->name,
                info->rs1,
                info->rs2
            );
            break;
        case PT_LD:
        case PT_CLD:
        case PT_CLDSP:
        case PT_I:
        case PT_CIRD5: // c.addi, c.addiw, c.li, c.addi16sp, c.lui
        case PT_CJALR: // c.jalr
            g_string_append_printf(report, "%s$rd@%hhu,$rs1@%hhu",
                info->info->name,
                info->rd,
                info->rs1
            );
            break;
        case PT_CIRD3:
            g_string_append_printf(report, "%s$rd@%hhu,$rs1@%hhu,$imm@%hhu",
                info->info->name,
                info->rd,
                info->rs1,
                info->imm
            );
            break;
        case PT_SHI6:
        case PT_SHI5:
        case PT_CSHRD3: // c.srli, c.srai
        case PT_CSHRD5: // c.slli
        case PT_CSH64RD3: // c.srli64, c.srai64
        case PT_CSH64RD5: // c.slli64
            g_string_append_printf(report, "%s$rd@%hhu,$rs1@%hhu,$sh@%hhu",
                info->info->name,
                info->rd,
                info->rs1,
                info->shamt
            );
            break;
        case PT_CJR: // c.jr
            g_string_append_printf(report, "%s$rs1@%hhu",
                info->info->name,
                info->rs1
            );
            break;
        default:
            g_string_append_printf(report, "%s",
                info->info->name
            );
            break;
    }
    qemu_plugin_outs(report->str);
}

static void plugin_exit(qemu_plugin_id_t id, void* p)
{
    // g_autoptr(GString) report = g_string_new("plugin_exit...\n");
    // g_string_append_printf(report, "size of instTable: %u\n", g_hash_table_size(instTable));

    GList* inst_it = g_hash_table_get_values(instTable);

    for (GList* it = inst_it; it; it = it->next) {
        InstInfo* thisInfo = (InstInfo*) it->data;
        // g_string_append_printf(report, "size of %s's follow_insts: %u\n", thisInfo->info->name, g_hash_table_size(thisInfo->follow_insts_cnt));
        GList* nit = g_hash_table_get_keys(thisInfo->follow_insts_cnt);
        for (; nit; nit = nit->next) {
            InstInfoHash nextHash = nit->data;
            InstInfo* nextInfo = (InstInfo*) g_hash_table_lookup(instTable, nextHash);
            uint64_t nextCnt = *(uint64_t*) g_hash_table_lookup(thisInfo->follow_insts_cnt, nextHash);
            print_inst(thisInfo);
            fprintf(stderr, "-");
            print_inst(nextInfo);
            fprintf(stderr, ":%lu\n", nextCnt);

            // g_string_append_printf(report, ":%lu\n", nextCnt);
        }
    }


    // qemu_plugin_outs(report->str);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    int i;

    if (strcmp(info->target_name, "riscv64") != 0)
        return -1;

    for (i = 0; i < argc; i++) {
        char *p = argv[i];
        g_autofree char **tokens = g_strsplit(p, "=", -1);
        if (g_strcmp0(tokens[0], "inline") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_inline)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", p);
                return -1;
            }
        } else {
            fprintf(stderr, "option parsing failed: %s\n", p);
            return -1;
        }
    }

    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

