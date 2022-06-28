
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>


#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum CountType {
    CT_CLASS,
    CT_INDIVIDUAL,
    CT_NONE
};

typedef struct InstCountInfo
{
    const char* type;
    const char* name;
    uint32_t mask;
    uint32_t pattern;
    uint8_t cnt_type;
    uint64_t cnt;
    GHashTable *follow_insts;
}InstCountInfo;

typedef struct BasicBlock
{
    uint64_t start_addr;
    GQueue *insts;               // inst patterns
    uint64_t exec_cnt;
    uint64_t trans_cnt;
}BasicBlock;

static GHashTable *pattern_map; // pattern -> InstCountInfo
static GQueue *block_que;       // start_addr
static GHashTable *block_map;   // start_addr -> BasicBlock
static uint64_t inst_cnt;
static bool do_inline;

static InstCountInfo riscv64_insns[] = {
    {"ecall",               "ecall", 0xffffffff, 0x00000073, CT_INDIVIDUAL},
    {"ebreak",              "ebreak", 0xffffffff, 0x00100073, CT_INDIVIDUAL},
    {"ret",                "uret", 0xffffffff, 0x00200073, CT_INDIVIDUAL},
    {"ret",                "sret", 0xffffffff, 0x10200073, CT_INDIVIDUAL},
    {"ret",                "mret", 0xffffffff, 0x30200073, CT_INDIVIDUAL},
    {"wfi",                 "wfi", 0xffffffff, 0x10500073, CT_INDIVIDUAL},
    {   "sfence_vma",          "sfence_vma", 0xfe007fff, 0x12000073, CT_INDIVIDUAL},
    {    "sfence_vm",           "sfence_vm", 0xfff07fff, 0x10400073, CT_INDIVIDUAL},
    {    "data_move",                 "lui", 0x0000007f, 0x00000037, CT_INDIVIDUAL},
    {          "alu",               "auipc", 0x0000007f, 0x00000017, CT_INDIVIDUAL},
    {            "j",                 "jal", 0x0000007f, 0x0000006f, CT_INDIVIDUAL},
    {            "i",                "jalr", 0x0000707f, 0x00000067, CT_INDIVIDUAL},
    {            "b",                 "beq", 0x0000707f, 0x00000063, CT_INDIVIDUAL},
    {            "b",                 "bne", 0x0000707f, 0x00001063, CT_INDIVIDUAL},
    {            "b",                 "blt", 0x0000707f, 0x00004063, CT_INDIVIDUAL},
    {            "b",                 "bge", 0x0000707f, 0x00005063, CT_INDIVIDUAL},
    {            "b",                "bltu", 0x0000707f, 0x00006063, CT_INDIVIDUAL},
    {            "b",                "bgeu", 0x0000707f, 0x00007063, CT_INDIVIDUAL},
    {            "i",                  "lb", 0x0000707f, 0x00000003, CT_INDIVIDUAL},
    {            "i",                  "lh", 0x0000707f, 0x00001003, CT_INDIVIDUAL},
    {            "i",                  "lw", 0x0000707f, 0x00002003, CT_INDIVIDUAL},
    {            "i",                 "lbu", 0x0000707f, 0x00004003, CT_INDIVIDUAL},
    {            "i",                 "lhu", 0x0000707f, 0x00005003, CT_INDIVIDUAL},
    {            "s",                  "sb", 0x0000707f, 0x00000023, CT_INDIVIDUAL},
    {            "s",                  "sh", 0x0000707f, 0x00001023, CT_INDIVIDUAL},
    {            "s",                  "sw", 0x0000707f, 0x00002023, CT_INDIVIDUAL},
    {            "i",                "addi", 0x0000707f, 0x00000013, CT_INDIVIDUAL},
    {            "i",                "slti", 0x0000707f, 0x00002013, CT_INDIVIDUAL},
    {            "i",               "sltiu", 0x0000707f, 0x00003013, CT_INDIVIDUAL},
    {            "i",                "xori", 0x0000707f, 0x00004013, CT_INDIVIDUAL},
    {            "i",                 "ori", 0x0000707f, 0x00006013, CT_INDIVIDUAL},
    {            "i",                "andi", 0x0000707f, 0x00007013, CT_INDIVIDUAL},
    {           "sh",                "slli", 0xf800707f, 0x00001013, CT_INDIVIDUAL},
    {           "sh",                "srli", 0xf800707f, 0x00005013, CT_INDIVIDUAL},
    {           "sh",                "srai", 0xf800707f, 0x40005013, CT_INDIVIDUAL},
    {            "r",                 "add", 0xfe00707f, 0x00000033, CT_INDIVIDUAL},
    {            "r",                 "sub", 0xfe00707f, 0x40000033, CT_INDIVIDUAL},
    {            "r",                 "sll", 0xfe00707f, 0x00001033, CT_INDIVIDUAL},
    {            "r",                 "slt", 0xfe00707f, 0x00002033, CT_INDIVIDUAL},
    {            "r",                "sltu", 0xfe00707f, 0x00003033, CT_INDIVIDUAL},
    {            "r",                 "xor", 0xfe00707f, 0x00004033, CT_INDIVIDUAL},
    {            "r",                 "srl", 0xfe00707f, 0x00005033, CT_INDIVIDUAL},
    {            "r",                 "sra", 0xfe00707f, 0x40005033, CT_INDIVIDUAL},
    {            "r",                  "or", 0xfe00707f, 0x00006033, CT_INDIVIDUAL},
    {            "r",                 "and", 0xfe00707f, 0x00007033, CT_INDIVIDUAL},
    {"decode_Fmt_32",               "fence", 0x0000707f, 0x0000000f, CT_INDIVIDUAL},
    {"decode_Fmt_31",             "fence_i", 0x0000707f, 0x0000100f, CT_INDIVIDUAL},
    {          "csr",               "csrrw", 0x0000707f, 0x00001073, CT_INDIVIDUAL},
    {          "csr",               "csrrs", 0x0000707f, 0x00002073, CT_INDIVIDUAL},
    {          "csr",               "csrrc", 0x0000707f, 0x00003073, CT_INDIVIDUAL},
    {          "csr",              "csrrwi", 0x0000707f, 0x00005073, CT_INDIVIDUAL},
    {          "csr",              "csrrsi", 0x0000707f, 0x00006073, CT_INDIVIDUAL},
    {          "csr",              "csrrci", 0x0000707f, 0x00007073, CT_INDIVIDUAL},
    {            "i",                 "lwu", 0x0000707f, 0x00006003, CT_INDIVIDUAL},
    {            "i",                  "ld", 0x0000707f, 0x00003003, CT_INDIVIDUAL},
    {            "s",                  "sd", 0x0000707f, 0x00003023, CT_INDIVIDUAL},
    {            "i",               "addiw", 0x0000707f, 0x0000001b, CT_INDIVIDUAL},
    {          "sh5",               "slliw", 0xfe00707f, 0x0000101b, CT_INDIVIDUAL},
    {          "sh5",               "srliw", 0xfe00707f, 0x0000501b, CT_INDIVIDUAL},
    {          "sh5",               "sraiw", 0xfe00707f, 0x4000501b, CT_INDIVIDUAL},
    {            "r",                "addw", 0xfe00707f, 0x0000003b, CT_INDIVIDUAL},
    {            "r",                "subw", 0xfe00707f, 0x4000003b, CT_INDIVIDUAL},
    {            "r",                "sllw", 0xfe00707f, 0x0000103b, CT_INDIVIDUAL},
    {            "r",                "srlw", 0xfe00707f, 0x0000503b, CT_INDIVIDUAL},
    {            "r",                "sraw", 0xfe00707f, 0x4000503b, CT_INDIVIDUAL},
    {            "i",                 "ldu", 0x0000707f, 0x00007003, CT_INDIVIDUAL},
    {            "i",                  "lq", 0x0000707f, 0x0000200f, CT_INDIVIDUAL},
    {            "s",                  "sq", 0x0000707f, 0x00004023, CT_INDIVIDUAL},
    {            "i",               "addid", 0x0000707f, 0x0000005b, CT_INDIVIDUAL},
    {          "sh6",               "sllid", 0xfc00707f, 0x0000105b, CT_INDIVIDUAL},
    {          "sh6",               "srlid", 0xfc00707f, 0x0000505b, CT_INDIVIDUAL},
    {          "sh6",               "sraid", 0xfc00707f, 0x4000505b, CT_INDIVIDUAL},
    {            "r",                "addd", 0xfe00707f, 0x0000007b, CT_INDIVIDUAL},
    {            "r",                "subd", 0xfe00707f, 0x4000007b, CT_INDIVIDUAL},
    {            "r",                "slld", 0xfe00707f, 0x0000107b, CT_INDIVIDUAL},
    {            "r",                "srld", 0xfe00707f, 0x0000507b, CT_INDIVIDUAL},
    {            "r",                "srad", 0xfe00707f, 0x4000507b, CT_INDIVIDUAL},
    {            "r",                 "mul", 0xfe00707f, 0x02000033, CT_INDIVIDUAL},
    {            "r",                "mulh", 0xfe00707f, 0x02001033, CT_INDIVIDUAL},
    {            "r",              "mulhsu", 0xfe00707f, 0x02002033, CT_INDIVIDUAL},
    {            "r",               "mulhu", 0xfe00707f, 0x02003033, CT_INDIVIDUAL},
    {            "r",                 "div", 0xfe00707f, 0x02004033, CT_INDIVIDUAL},
    {            "r",                "divu", 0xfe00707f, 0x02005033, CT_INDIVIDUAL},
    {            "r",                 "rem", 0xfe00707f, 0x02006033, CT_INDIVIDUAL},
    {            "r",                "remu", 0xfe00707f, 0x02007033, CT_INDIVIDUAL},
    {            "r",                "mulw", 0xfe00707f, 0x0200003b, CT_INDIVIDUAL},
    {            "r",                "divw", 0xfe00707f, 0x0200403b, CT_INDIVIDUAL},
    {            "r",               "divuw", 0xfe00707f, 0x0200503b, CT_INDIVIDUAL},
    {            "r",                "remw", 0xfe00707f, 0x0200603b, CT_INDIVIDUAL},
    {            "r",               "remuw", 0xfe00707f, 0x0200703b, CT_INDIVIDUAL},
    {            "r",                "muld", 0xfe00707f, 0x0200007b, CT_INDIVIDUAL},
    {            "r",                "divd", 0xfe00707f, 0x0200407b, CT_INDIVIDUAL},
    {            "r",               "divud", 0xfe00707f, 0x0200507b, CT_INDIVIDUAL},
    {            "r",                "remd", 0xfe00707f, 0x0200607b, CT_INDIVIDUAL},
    {            "r",               "remud", 0xfe00707f, 0x0200707b, CT_INDIVIDUAL},
    {      "atom_ld",                "lr_w", 0xf9f0707f, 0x1000202f, CT_INDIVIDUAL},
    {      "atom_st",                "sc_w", 0xf800707f, 0x1800202f, CT_INDIVIDUAL},
    {      "atom_st",           "amoswap_w", 0xf800707f, 0x0800202f, CT_INDIVIDUAL},
    {      "atom_st",            "amoadd_w", 0xf800707f, 0x0000202f, CT_INDIVIDUAL},
    {      "atom_st",            "amoxor_w", 0xf800707f, 0x2000202f, CT_INDIVIDUAL},
    {      "atom_st",            "amoand_w", 0xf800707f, 0x6000202f, CT_INDIVIDUAL},
    {      "atom_st",             "amoor_w", 0xf800707f, 0x4000202f, CT_INDIVIDUAL},
    {      "atom_st",            "amomin_w", 0xf800707f, 0x8000202f, CT_INDIVIDUAL},
    {      "atom_st",            "amomax_w", 0xf800707f, 0xa000202f, CT_INDIVIDUAL},
    {      "atom_st",           "amominu_w", 0xf800707f, 0xc000202f, CT_INDIVIDUAL},
    {      "atom_st",           "amomaxu_w", 0xf800707f, 0xe000202f, CT_INDIVIDUAL},
    {      "atom_ld",                "lr_d", 0xf9f0707f, 0x1000302f, CT_INDIVIDUAL},
    {      "atom_st",                "sc_d", 0xf800707f, 0x1800302f, CT_INDIVIDUAL},
    {      "atom_st",           "amoswap_d", 0xf800707f, 0x0800302f, CT_INDIVIDUAL},
    {      "atom_st",            "amoadd_d", 0xf800707f, 0x0000302f, CT_INDIVIDUAL},
    {      "atom_st",            "amoxor_d", 0xf800707f, 0x2000302f, CT_INDIVIDUAL},
    {      "atom_st",            "amoand_d", 0xf800707f, 0x6000302f, CT_INDIVIDUAL},
    {      "atom_st",             "amoor_d", 0xf800707f, 0x4000302f, CT_INDIVIDUAL},
    {      "atom_st",            "amomin_d", 0xf800707f, 0x8000302f, CT_INDIVIDUAL},
    {      "atom_st",            "amomax_d", 0xf800707f, 0xa000302f, CT_INDIVIDUAL},
    {      "atom_st",           "amominu_d", 0xf800707f, 0xc000302f, CT_INDIVIDUAL},
    {      "atom_st",           "amomaxu_d", 0xf800707f, 0xe000302f, CT_INDIVIDUAL},
    {            "i",                 "flw", 0x0000707f, 0x00002007, CT_INDIVIDUAL},
    {            "s",                 "fsw", 0x0000707f, 0x00002027, CT_INDIVIDUAL},
    {        "r4_rm",             "fmadd_s", 0x0600007f, 0x00000043, CT_INDIVIDUAL},
    {        "r4_rm",             "fmsub_s", 0x0600007f, 0x00000047, CT_INDIVIDUAL},
    {        "r4_rm",            "fnmsub_s", 0x0600007f, 0x0000004b, CT_INDIVIDUAL},
    {        "r4_rm",            "fnmadd_s", 0x0600007f, 0x0000004f, CT_INDIVIDUAL},
    {         "r_rm",              "fadd_s", 0xfe00007f, 0x00000053, CT_INDIVIDUAL},
    {         "r_rm",              "fsub_s", 0xfe00007f, 0x08000053, CT_INDIVIDUAL},
    {         "r_rm",              "fmul_s", 0xfe00007f, 0x10000053, CT_INDIVIDUAL},
    {         "r_rm",              "fdiv_s", 0xfe00007f, 0x18000053, CT_INDIVIDUAL},
    {        "r2_rm",             "fsqrt_s", 0xfff0007f, 0x58000053, CT_INDIVIDUAL},
    {            "r",             "fsgnj_s", 0xfe00707f, 0x20000053, CT_INDIVIDUAL},
    {            "r",            "fsgnjn_s", 0xfe00707f, 0x20001053, CT_INDIVIDUAL},
    {            "r",            "fsgnjx_s", 0xfe00707f, 0x20002053, CT_INDIVIDUAL},
    {            "r",              "fmin_s", 0xfe00707f, 0x28000053, CT_INDIVIDUAL},
    {            "r",              "fmax_s", 0xfe00707f, 0x28001053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_w_s", 0xfff0007f, 0xc0000053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_wu_s", 0xfff0007f, 0xc0100053, CT_INDIVIDUAL},
    {           "r2",             "fmv_x_w", 0xfff0707f, 0xe0000053, CT_INDIVIDUAL},
    {            "r",               "feq_s", 0xfe00707f, 0xa0002053, CT_INDIVIDUAL},
    {            "r",               "flt_s", 0xfe00707f, 0xa0001053, CT_INDIVIDUAL},
    {            "r",               "fle_s", 0xfe00707f, 0xa0000053, CT_INDIVIDUAL},
    {           "r2",            "fclass_s", 0xfff0707f, 0xe0001053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_s_w", 0xfff0007f, 0xd0000053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_s_wu", 0xfff0007f, 0xd0100053, CT_INDIVIDUAL},
    {           "r2",             "fmv_w_x", 0xfff0707f, 0xf0000053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_l_s", 0xfff0007f, 0xc0200053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_lu_s", 0xfff0007f, 0xc0300053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_s_l", 0xfff0007f, 0xd0200053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_s_lu", 0xfff0007f, 0xd0300053, CT_INDIVIDUAL},
    {            "i",                 "fld", 0x0000707f, 0x00003007, CT_INDIVIDUAL},
    {            "s",                 "fsd", 0x0000707f, 0x00003027, CT_INDIVIDUAL},
    {        "r4_rm",             "fmadd_d", 0x0600007f, 0x02000043, CT_INDIVIDUAL},
    {        "r4_rm",             "fmsub_d", 0x0600007f, 0x02000047, CT_INDIVIDUAL},
    {        "r4_rm",            "fnmsub_d", 0x0600007f, 0x0200004b, CT_INDIVIDUAL},
    {        "r4_rm",            "fnmadd_d", 0x0600007f, 0x0200004f, CT_INDIVIDUAL},
    {         "r_rm",              "fadd_d", 0xfe00007f, 0x02000053, CT_INDIVIDUAL},
    {         "r_rm",              "fsub_d", 0xfe00007f, 0x0a000053, CT_INDIVIDUAL},
    {         "r_rm",              "fmul_d", 0xfe00007f, 0x12000053, CT_INDIVIDUAL},
    {         "r_rm",              "fdiv_d", 0xfe00007f, 0x1a000053, CT_INDIVIDUAL},
    {        "r2_rm",             "fsqrt_d", 0xfff0007f, 0x5a000053, CT_INDIVIDUAL},
    {            "r",             "fsgnj_d", 0xfe00707f, 0x22000053, CT_INDIVIDUAL},
    {            "r",            "fsgnjn_d", 0xfe00707f, 0x22001053, CT_INDIVIDUAL},
    {            "r",            "fsgnjx_d", 0xfe00707f, 0x22002053, CT_INDIVIDUAL},
    {            "r",              "fmin_d", 0xfe00707f, 0x2a000053, CT_INDIVIDUAL},
    {            "r",              "fmax_d", 0xfe00707f, 0x2a001053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_s_d", 0xfff0007f, 0x40100053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_d_s", 0xfff0007f, 0x42000053, CT_INDIVIDUAL},
    {            "r",               "feq_d", 0xfe00707f, 0xa2002053, CT_INDIVIDUAL},
    {            "r",               "flt_d", 0xfe00707f, 0xa2001053, CT_INDIVIDUAL},
    {            "r",               "fle_d", 0xfe00707f, 0xa2000053, CT_INDIVIDUAL},
    {           "r2",            "fclass_d", 0xfff0707f, 0xe2001053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_w_d", 0xfff0007f, 0xc2000053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_wu_d", 0xfff0007f, 0xc2100053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_d_w", 0xfff0007f, 0xd2000053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_d_wu", 0xfff0007f, 0xd2100053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_l_d", 0xfff0007f, 0xc2200053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_lu_d", 0xfff0007f, 0xc2300053, CT_INDIVIDUAL},
    {           "r2",             "fmv_x_d", 0xfff0707f, 0xe2000053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_d_l", 0xfff0007f, 0xd2200053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_d_lu", 0xfff0007f, 0xd2300053, CT_INDIVIDUAL},
    {           "r2",             "fmv_d_x", 0xfff0707f, 0xf2000053, CT_INDIVIDUAL},
    {           "r2",               "hlv_b", 0xfff0707f, 0x60004073, CT_INDIVIDUAL},
    {           "r2",              "hlv_bu", 0xfff0707f, 0x60104073, CT_INDIVIDUAL},
    {           "r2",               "hlv_h", 0xfff0707f, 0x64004073, CT_INDIVIDUAL},
    {           "r2",              "hlv_hu", 0xfff0707f, 0x64104073, CT_INDIVIDUAL},
    {           "r2",             "hlvx_hu", 0xfff0707f, 0x64304073, CT_INDIVIDUAL},
    {           "r2",               "hlv_w", 0xfff0707f, 0x68004073, CT_INDIVIDUAL},
    {           "r2",             "hlvx_wu", 0xfff0707f, 0x68304073, CT_INDIVIDUAL},
    {         "r2_s",               "hsv_b", 0xfe007fff, 0x62004073, CT_INDIVIDUAL},
    {         "r2_s",               "hsv_h", 0xfe007fff, 0x66004073, CT_INDIVIDUAL},
    {         "r2_s",               "hsv_w", 0xfe007fff, 0x6a004073, CT_INDIVIDUAL},
    {  "hfence_gvma",         "hfence_gvma", 0xfe007fff, 0x62000073, CT_INDIVIDUAL},
    {  "hfence_vvma",         "hfence_vvma", 0xfe007fff, 0x22000073, CT_INDIVIDUAL},
    {           "r2",              "hlv_wu", 0xfff0707f, 0x68104073, CT_INDIVIDUAL},
    {           "r2",               "hlv_d", 0xfff0707f, 0x6c004073, CT_INDIVIDUAL},
    {         "r2_s",               "hsv_d", 0xfe007fff, 0x6e004073, CT_INDIVIDUAL},
    {      "r2_nfvm",              "vle8_v", 0x1df0707f, 0x00000007, CT_INDIVIDUAL},
    {      "r2_nfvm",             "vle16_v", 0x1df0707f, 0x00005007, CT_INDIVIDUAL},
    {      "r2_nfvm",             "vle32_v", 0x1df0707f, 0x00006007, CT_INDIVIDUAL},
    {      "r2_nfvm",             "vle64_v", 0x1df0707f, 0x00007007, CT_INDIVIDUAL},
    {      "r2_nfvm",              "vse8_v", 0x1df0707f, 0x00000027, CT_INDIVIDUAL},
    {      "r2_nfvm",             "vse16_v", 0x1df0707f, 0x00005027, CT_INDIVIDUAL},
    {      "r2_nfvm",             "vse32_v", 0x1df0707f, 0x00006027, CT_INDIVIDUAL},
    {      "r2_nfvm",             "vse64_v", 0x1df0707f, 0x00007027, CT_INDIVIDUAL},
    {           "r2",               "vlm_v", 0xfff0707f, 0x02b00007, CT_INDIVIDUAL},
    {           "r2",               "vsm_v", 0xfff0707f, 0x02b00027, CT_INDIVIDUAL},
    {       "r_nfvm",             "vlse8_v", 0x1c00707f, 0x08000007, CT_INDIVIDUAL},
    {       "r_nfvm",            "vlse16_v", 0x1c00707f, 0x08005007, CT_INDIVIDUAL},
    {       "r_nfvm",            "vlse32_v", 0x1c00707f, 0x08006007, CT_INDIVIDUAL},
    {       "r_nfvm",            "vlse64_v", 0x1c00707f, 0x08007007, CT_INDIVIDUAL},
    {       "r_nfvm",             "vsse8_v", 0x1c00707f, 0x08000027, CT_INDIVIDUAL},
    {       "r_nfvm",            "vsse16_v", 0x1c00707f, 0x08005027, CT_INDIVIDUAL},
    {       "r_nfvm",            "vsse32_v", 0x1c00707f, 0x08006027, CT_INDIVIDUAL},
    {       "r_nfvm",            "vsse64_v", 0x1c00707f, 0x08007027, CT_INDIVIDUAL},
    {       "r_nfvm",            "vlxei8_v", 0x1400707f, 0x04000007, CT_INDIVIDUAL},
    {       "r_nfvm",           "vlxei16_v", 0x1400707f, 0x04005007, CT_INDIVIDUAL},
    {       "r_nfvm",           "vlxei32_v", 0x1400707f, 0x04006007, CT_INDIVIDUAL},
    {       "r_nfvm",           "vlxei64_v", 0x1400707f, 0x04007007, CT_INDIVIDUAL},
    {       "r_nfvm",            "vsxei8_v", 0x1400707f, 0x04000027, CT_INDIVIDUAL},
    {       "r_nfvm",           "vsxei16_v", 0x1400707f, 0x04005027, CT_INDIVIDUAL},
    {       "r_nfvm",           "vsxei32_v", 0x1400707f, 0x04006027, CT_INDIVIDUAL},
    {       "r_nfvm",           "vsxei64_v", 0x1400707f, 0x04007027, CT_INDIVIDUAL},
    {      "r2_nfvm",            "vle8ff_v", 0x1df0707f, 0x01000007, CT_INDIVIDUAL},
    {      "r2_nfvm",           "vle16ff_v", 0x1df0707f, 0x01005007, CT_INDIVIDUAL},
    {      "r2_nfvm",           "vle32ff_v", 0x1df0707f, 0x01006007, CT_INDIVIDUAL},
    {      "r2_nfvm",           "vle64ff_v", 0x1df0707f, 0x01007007, CT_INDIVIDUAL},
    {           "r2",            "vl1re8_v", 0xfff0707f, 0x02800007, CT_INDIVIDUAL},
    {           "r2",           "vl1re16_v", 0xfff0707f, 0x02805007, CT_INDIVIDUAL},
    {           "r2",           "vl1re32_v", 0xfff0707f, 0x02806007, CT_INDIVIDUAL},
    {           "r2",           "vl1re64_v", 0xfff0707f, 0x02807007, CT_INDIVIDUAL},
    {           "r2",            "vl2re8_v", 0xfff0707f, 0x22800007, CT_INDIVIDUAL},
    {           "r2",           "vl2re16_v", 0xfff0707f, 0x22805007, CT_INDIVIDUAL},
    {           "r2",           "vl2re32_v", 0xfff0707f, 0x22806007, CT_INDIVIDUAL},
    {           "r2",           "vl2re64_v", 0xfff0707f, 0x22807007, CT_INDIVIDUAL},
    {           "r2",            "vl4re8_v", 0xfff0707f, 0x62800007, CT_INDIVIDUAL},
    {           "r2",           "vl4re16_v", 0xfff0707f, 0x62805007, CT_INDIVIDUAL},
    {           "r2",           "vl4re32_v", 0xfff0707f, 0x62806007, CT_INDIVIDUAL},
    {           "r2",           "vl4re64_v", 0xfff0707f, 0x62807007, CT_INDIVIDUAL},
    {           "r2",            "vl8re8_v", 0xfff0707f, 0xe2800007, CT_INDIVIDUAL},
    {           "r2",           "vl8re16_v", 0xfff0707f, 0xe2805007, CT_INDIVIDUAL},
    {           "r2",           "vl8re32_v", 0xfff0707f, 0xe2806007, CT_INDIVIDUAL},
    {           "r2",           "vl8re64_v", 0xfff0707f, 0xe2807007, CT_INDIVIDUAL},
    {           "r2",              "vs1r_v", 0xfff0707f, 0x02800027, CT_INDIVIDUAL},
    {           "r2",              "vs2r_v", 0xfff0707f, 0x22800027, CT_INDIVIDUAL},
    {           "r2",              "vs4r_v", 0xfff0707f, 0x62800027, CT_INDIVIDUAL},
    {           "r2",              "vs8r_v", 0xfff0707f, 0xe2800027, CT_INDIVIDUAL},
    {         "r_vm",             "vadd_vv", 0xfc00707f, 0x00000057, CT_INDIVIDUAL},
    {         "r_vm",             "vadd_vx", 0xfc00707f, 0x00004057, CT_INDIVIDUAL},
    {         "r_vm",             "vadd_vi", 0xfc00707f, 0x00003057, CT_INDIVIDUAL},
    {         "r_vm",             "vsub_vv", 0xfc00707f, 0x08000057, CT_INDIVIDUAL},
    {         "r_vm",             "vsub_vx", 0xfc00707f, 0x08004057, CT_INDIVIDUAL},
    {         "r_vm",            "vrsub_vx", 0xfc00707f, 0x0c004057, CT_INDIVIDUAL},
    {         "r_vm",            "vrsub_vi", 0xfc00707f, 0x0c003057, CT_INDIVIDUAL},
    {         "r_vm",           "vwaddu_vv", 0xfc00707f, 0xc0002057, CT_INDIVIDUAL},
    {         "r_vm",           "vwaddu_vx", 0xfc00707f, 0xc0006057, CT_INDIVIDUAL},
    {         "r_vm",            "vwadd_vv", 0xfc00707f, 0xc4002057, CT_INDIVIDUAL},
    {         "r_vm",            "vwadd_vx", 0xfc00707f, 0xc4006057, CT_INDIVIDUAL},
    {         "r_vm",           "vwsubu_vv", 0xfc00707f, 0xc8002057, CT_INDIVIDUAL},
    {         "r_vm",           "vwsubu_vx", 0xfc00707f, 0xc8006057, CT_INDIVIDUAL},
    {         "r_vm",            "vwsub_vv", 0xfc00707f, 0xcc002057, CT_INDIVIDUAL},
    {         "r_vm",            "vwsub_vx", 0xfc00707f, 0xcc006057, CT_INDIVIDUAL},
    {         "r_vm",           "vwaddu_wv", 0xfc00707f, 0xd0002057, CT_INDIVIDUAL},
    {         "r_vm",           "vwaddu_wx", 0xfc00707f, 0xd0006057, CT_INDIVIDUAL},
    {         "r_vm",            "vwadd_wv", 0xfc00707f, 0xd4002057, CT_INDIVIDUAL},
    {         "r_vm",            "vwadd_wx", 0xfc00707f, 0xd4006057, CT_INDIVIDUAL},
    {         "r_vm",           "vwsubu_wv", 0xfc00707f, 0xd8002057, CT_INDIVIDUAL},
    {         "r_vm",           "vwsubu_wx", 0xfc00707f, 0xd8006057, CT_INDIVIDUAL},
    {         "r_vm",            "vwsub_wv", 0xfc00707f, 0xdc002057, CT_INDIVIDUAL},
    {         "r_vm",            "vwsub_wx", 0xfc00707f, 0xdc006057, CT_INDIVIDUAL},
    {       "r_vm_1",            "vadc_vvm", 0xfe00707f, 0x40000057, CT_INDIVIDUAL},
    {       "r_vm_1",            "vadc_vxm", 0xfe00707f, 0x40004057, CT_INDIVIDUAL},
    {       "r_vm_1",            "vadc_vim", 0xfe00707f, 0x40003057, CT_INDIVIDUAL},
    {         "r_vm",           "vmadc_vvm", 0xfc00707f, 0x44000057, CT_INDIVIDUAL},
    {         "r_vm",           "vmadc_vxm", 0xfc00707f, 0x44004057, CT_INDIVIDUAL},
    {         "r_vm",           "vmadc_vim", 0xfc00707f, 0x44003057, CT_INDIVIDUAL},
    {       "r_vm_1",            "vsbc_vvm", 0xfe00707f, 0x48000057, CT_INDIVIDUAL},
    {       "r_vm_1",            "vsbc_vxm", 0xfe00707f, 0x48004057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsbc_vvm", 0xfc00707f, 0x4c000057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsbc_vxm", 0xfc00707f, 0x4c004057, CT_INDIVIDUAL},
    {         "r_vm",             "vand_vv", 0xfc00707f, 0x24000057, CT_INDIVIDUAL},
    {         "r_vm",             "vand_vx", 0xfc00707f, 0x24004057, CT_INDIVIDUAL},
    {         "r_vm",             "vand_vi", 0xfc00707f, 0x24003057, CT_INDIVIDUAL},
    {         "r_vm",              "vor_vv", 0xfc00707f, 0x28000057, CT_INDIVIDUAL},
    {         "r_vm",              "vor_vx", 0xfc00707f, 0x28004057, CT_INDIVIDUAL},
    {         "r_vm",              "vor_vi", 0xfc00707f, 0x28003057, CT_INDIVIDUAL},
    {         "r_vm",             "vxor_vv", 0xfc00707f, 0x2c000057, CT_INDIVIDUAL},
    {         "r_vm",             "vxor_vx", 0xfc00707f, 0x2c004057, CT_INDIVIDUAL},
    {         "r_vm",             "vxor_vi", 0xfc00707f, 0x2c003057, CT_INDIVIDUAL},
    {         "r_vm",             "vsll_vv", 0xfc00707f, 0x94000057, CT_INDIVIDUAL},
    {         "r_vm",             "vsll_vx", 0xfc00707f, 0x94004057, CT_INDIVIDUAL},
    {         "r_vm",             "vsll_vi", 0xfc00707f, 0x94003057, CT_INDIVIDUAL},
    {         "r_vm",             "vsrl_vv", 0xfc00707f, 0xa0000057, CT_INDIVIDUAL},
    {         "r_vm",             "vsrl_vx", 0xfc00707f, 0xa0004057, CT_INDIVIDUAL},
    {         "r_vm",             "vsrl_vi", 0xfc00707f, 0xa0003057, CT_INDIVIDUAL},
    {         "r_vm",             "vsra_vv", 0xfc00707f, 0xa4000057, CT_INDIVIDUAL},
    {         "r_vm",             "vsra_vx", 0xfc00707f, 0xa4004057, CT_INDIVIDUAL},
    {         "r_vm",             "vsra_vi", 0xfc00707f, 0xa4003057, CT_INDIVIDUAL},
    {         "r_vm",            "vnsrl_wv", 0xfc00707f, 0xb0000057, CT_INDIVIDUAL},
    {         "r_vm",            "vnsrl_wx", 0xfc00707f, 0xb0004057, CT_INDIVIDUAL},
    {         "r_vm",            "vnsrl_wi", 0xfc00707f, 0xb0003057, CT_INDIVIDUAL},
    {         "r_vm",            "vnsra_wv", 0xfc00707f, 0xb4000057, CT_INDIVIDUAL},
    {         "r_vm",            "vnsra_wx", 0xfc00707f, 0xb4004057, CT_INDIVIDUAL},
    {         "r_vm",            "vnsra_wi", 0xfc00707f, 0xb4003057, CT_INDIVIDUAL},
    {         "r_vm",            "vmseq_vv", 0xfc00707f, 0x60000057, CT_INDIVIDUAL},
    {         "r_vm",            "vmseq_vx", 0xfc00707f, 0x60004057, CT_INDIVIDUAL},
    {         "r_vm",            "vmseq_vi", 0xfc00707f, 0x60003057, CT_INDIVIDUAL},
    {         "r_vm",            "vmsne_vv", 0xfc00707f, 0x64000057, CT_INDIVIDUAL},
    {         "r_vm",            "vmsne_vx", 0xfc00707f, 0x64004057, CT_INDIVIDUAL},
    {         "r_vm",            "vmsne_vi", 0xfc00707f, 0x64003057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsltu_vv", 0xfc00707f, 0x68000057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsltu_vx", 0xfc00707f, 0x68004057, CT_INDIVIDUAL},
    {         "r_vm",            "vmslt_vv", 0xfc00707f, 0x6c000057, CT_INDIVIDUAL},
    {         "r_vm",            "vmslt_vx", 0xfc00707f, 0x6c004057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsleu_vv", 0xfc00707f, 0x70000057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsleu_vx", 0xfc00707f, 0x70004057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsleu_vi", 0xfc00707f, 0x70003057, CT_INDIVIDUAL},
    {         "r_vm",            "vmsle_vv", 0xfc00707f, 0x74000057, CT_INDIVIDUAL},
    {         "r_vm",            "vmsle_vx", 0xfc00707f, 0x74004057, CT_INDIVIDUAL},
    {         "r_vm",            "vmsle_vi", 0xfc00707f, 0x74003057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsgtu_vx", 0xfc00707f, 0x78004057, CT_INDIVIDUAL},
    {         "r_vm",           "vmsgtu_vi", 0xfc00707f, 0x78003057, CT_INDIVIDUAL},
    {         "r_vm",            "vmsgt_vx", 0xfc00707f, 0x7c004057, CT_INDIVIDUAL},
    {         "r_vm",            "vmsgt_vi", 0xfc00707f, 0x7c003057, CT_INDIVIDUAL},
    {         "r_vm",            "vminu_vv", 0xfc00707f, 0x10000057, CT_INDIVIDUAL},
    {         "r_vm",            "vminu_vx", 0xfc00707f, 0x10004057, CT_INDIVIDUAL},
    {         "r_vm",             "vmin_vv", 0xfc00707f, 0x14000057, CT_INDIVIDUAL},
    {         "r_vm",             "vmin_vx", 0xfc00707f, 0x14004057, CT_INDIVIDUAL},
    {         "r_vm",            "vmaxu_vv", 0xfc00707f, 0x18000057, CT_INDIVIDUAL},
    {         "r_vm",            "vmaxu_vx", 0xfc00707f, 0x18004057, CT_INDIVIDUAL},
    {         "r_vm",             "vmax_vv", 0xfc00707f, 0x1c000057, CT_INDIVIDUAL},
    {         "r_vm",             "vmax_vx", 0xfc00707f, 0x1c004057, CT_INDIVIDUAL},
    {         "r_vm",             "vmul_vv", 0xfc00707f, 0x94002057, CT_INDIVIDUAL},
    {         "r_vm",             "vmul_vx", 0xfc00707f, 0x94006057, CT_INDIVIDUAL},
    {         "r_vm",            "vmulh_vv", 0xfc00707f, 0x9c002057, CT_INDIVIDUAL},
    {         "r_vm",            "vmulh_vx", 0xfc00707f, 0x9c006057, CT_INDIVIDUAL},
    {         "r_vm",           "vmulhu_vv", 0xfc00707f, 0x90002057, CT_INDIVIDUAL},
    {         "r_vm",           "vmulhu_vx", 0xfc00707f, 0x90006057, CT_INDIVIDUAL},
    {         "r_vm",          "vmulhsu_vv", 0xfc00707f, 0x98002057, CT_INDIVIDUAL},
    {         "r_vm",          "vmulhsu_vx", 0xfc00707f, 0x98006057, CT_INDIVIDUAL},
    {         "r_vm",            "vdivu_vv", 0xfc00707f, 0x80002057, CT_INDIVIDUAL},
    {         "r_vm",            "vdivu_vx", 0xfc00707f, 0x80006057, CT_INDIVIDUAL},
    {         "r_vm",             "vdiv_vv", 0xfc00707f, 0x84002057, CT_INDIVIDUAL},
    {         "r_vm",             "vdiv_vx", 0xfc00707f, 0x84006057, CT_INDIVIDUAL},
    {         "r_vm",            "vremu_vv", 0xfc00707f, 0x88002057, CT_INDIVIDUAL},
    {         "r_vm",            "vremu_vx", 0xfc00707f, 0x88006057, CT_INDIVIDUAL},
    {         "r_vm",             "vrem_vv", 0xfc00707f, 0x8c002057, CT_INDIVIDUAL},
    {         "r_vm",             "vrem_vx", 0xfc00707f, 0x8c006057, CT_INDIVIDUAL},
    {         "r_vm",           "vwmulu_vv", 0xfc00707f, 0xe0002057, CT_INDIVIDUAL},
    {         "r_vm",           "vwmulu_vx", 0xfc00707f, 0xe0006057, CT_INDIVIDUAL},
    {         "r_vm",          "vwmulsu_vv", 0xfc00707f, 0xe8002057, CT_INDIVIDUAL},
    {         "r_vm",          "vwmulsu_vx", 0xfc00707f, 0xe8006057, CT_INDIVIDUAL},
    {         "r_vm",            "vwmul_vv", 0xfc00707f, 0xec002057, CT_INDIVIDUAL},
    {         "r_vm",            "vwmul_vx", 0xfc00707f, 0xec006057, CT_INDIVIDUAL},
    {         "r_vm",            "vmacc_vv", 0xfc00707f, 0xb4002057, CT_INDIVIDUAL},
    {         "r_vm",            "vmacc_vx", 0xfc00707f, 0xb4006057, CT_INDIVIDUAL},
    {         "r_vm",           "vnmsac_vv", 0xfc00707f, 0xbc002057, CT_INDIVIDUAL},
    {         "r_vm",           "vnmsac_vx", 0xfc00707f, 0xbc006057, CT_INDIVIDUAL},
    {         "r_vm",            "vmadd_vv", 0xfc00707f, 0xa4002057, CT_INDIVIDUAL},
    {         "r_vm",            "vmadd_vx", 0xfc00707f, 0xa4006057, CT_INDIVIDUAL},
    {         "r_vm",           "vnmsub_vv", 0xfc00707f, 0xac002057, CT_INDIVIDUAL},
    {         "r_vm",           "vnmsub_vx", 0xfc00707f, 0xac006057, CT_INDIVIDUAL},
    {         "r_vm",          "vwmaccu_vv", 0xfc00707f, 0xf0002057, CT_INDIVIDUAL},
    {         "r_vm",          "vwmaccu_vx", 0xfc00707f, 0xf0006057, CT_INDIVIDUAL},
    {         "r_vm",           "vwmacc_vv", 0xfc00707f, 0xf4002057, CT_INDIVIDUAL},
    {         "r_vm",           "vwmacc_vx", 0xfc00707f, 0xf4006057, CT_INDIVIDUAL},
    {         "r_vm",         "vwmaccsu_vv", 0xfc00707f, 0xfc002057, CT_INDIVIDUAL},
    {         "r_vm",         "vwmaccsu_vx", 0xfc00707f, 0xfc006057, CT_INDIVIDUAL},
    {         "r_vm",         "vwmaccus_vx", 0xfc00707f, 0xf8006057, CT_INDIVIDUAL},
    {           "r2",             "vmv_v_v", 0xfff0707f, 0x5e000057, CT_INDIVIDUAL},
    {           "r2",             "vmv_v_x", 0xfff0707f, 0x5e004057, CT_INDIVIDUAL},
    {           "r2",             "vmv_v_i", 0xfff0707f, 0x5e003057, CT_INDIVIDUAL},
    {       "r_vm_0",          "vmerge_vvm", 0xfe00707f, 0x5c000057, CT_INDIVIDUAL},
    {       "r_vm_0",          "vmerge_vxm", 0xfe00707f, 0x5c004057, CT_INDIVIDUAL},
    {       "r_vm_0",          "vmerge_vim", 0xfe00707f, 0x5c003057, CT_INDIVIDUAL},
    {         "r_vm",           "vsaddu_vv", 0xfc00707f, 0x80000057, CT_INDIVIDUAL},
    {         "r_vm",           "vsaddu_vx", 0xfc00707f, 0x80004057, CT_INDIVIDUAL},
    {         "r_vm",           "vsaddu_vi", 0xfc00707f, 0x80003057, CT_INDIVIDUAL},
    {         "r_vm",            "vsadd_vv", 0xfc00707f, 0x84000057, CT_INDIVIDUAL},
    {         "r_vm",            "vsadd_vx", 0xfc00707f, 0x84004057, CT_INDIVIDUAL},
    {         "r_vm",            "vsadd_vi", 0xfc00707f, 0x84003057, CT_INDIVIDUAL},
    {         "r_vm",           "vssubu_vv", 0xfc00707f, 0x88000057, CT_INDIVIDUAL},
    {         "r_vm",           "vssubu_vx", 0xfc00707f, 0x88004057, CT_INDIVIDUAL},
    {         "r_vm",            "vssub_vv", 0xfc00707f, 0x8c000057, CT_INDIVIDUAL},
    {         "r_vm",            "vssub_vx", 0xfc00707f, 0x8c004057, CT_INDIVIDUAL},
    {         "r_vm",            "vaadd_vv", 0xfc00707f, 0x24002057, CT_INDIVIDUAL},
    {         "r_vm",            "vaadd_vx", 0xfc00707f, 0x24006057, CT_INDIVIDUAL},
    {         "r_vm",           "vaaddu_vv", 0xfc00707f, 0x20002057, CT_INDIVIDUAL},
    {         "r_vm",           "vaaddu_vx", 0xfc00707f, 0x20006057, CT_INDIVIDUAL},
    {         "r_vm",            "vasub_vv", 0xfc00707f, 0x2c002057, CT_INDIVIDUAL},
    {         "r_vm",            "vasub_vx", 0xfc00707f, 0x2c006057, CT_INDIVIDUAL},
    {         "r_vm",           "vasubu_vv", 0xfc00707f, 0x28002057, CT_INDIVIDUAL},
    {         "r_vm",           "vasubu_vx", 0xfc00707f, 0x28006057, CT_INDIVIDUAL},
    {         "r_vm",            "vsmul_vv", 0xfc00707f, 0x9c000057, CT_INDIVIDUAL},
    {         "r_vm",            "vsmul_vx", 0xfc00707f, 0x9c004057, CT_INDIVIDUAL},
    {         "r_vm",            "vssrl_vv", 0xfc00707f, 0xa8000057, CT_INDIVIDUAL},
    {         "r_vm",            "vssrl_vx", 0xfc00707f, 0xa8004057, CT_INDIVIDUAL},
    {         "r_vm",            "vssrl_vi", 0xfc00707f, 0xa8003057, CT_INDIVIDUAL},
    {         "r_vm",            "vssra_vv", 0xfc00707f, 0xac000057, CT_INDIVIDUAL},
    {         "r_vm",            "vssra_vx", 0xfc00707f, 0xac004057, CT_INDIVIDUAL},
    {         "r_vm",            "vssra_vi", 0xfc00707f, 0xac003057, CT_INDIVIDUAL},
    {         "r_vm",          "vnclipu_wv", 0xfc00707f, 0xb8000057, CT_INDIVIDUAL},
    {         "r_vm",          "vnclipu_wx", 0xfc00707f, 0xb8004057, CT_INDIVIDUAL},
    {         "r_vm",          "vnclipu_wi", 0xfc00707f, 0xb8003057, CT_INDIVIDUAL},
    {         "r_vm",           "vnclip_wv", 0xfc00707f, 0xbc000057, CT_INDIVIDUAL},
    {         "r_vm",           "vnclip_wx", 0xfc00707f, 0xbc004057, CT_INDIVIDUAL},
    {         "r_vm",           "vnclip_wi", 0xfc00707f, 0xbc003057, CT_INDIVIDUAL},
    {         "r_vm",            "vfadd_vv", 0xfc00707f, 0x00001057, CT_INDIVIDUAL},
    {         "r_vm",            "vfadd_vf", 0xfc00707f, 0x00005057, CT_INDIVIDUAL},
    {         "r_vm",            "vfsub_vv", 0xfc00707f, 0x08001057, CT_INDIVIDUAL},
    {         "r_vm",            "vfsub_vf", 0xfc00707f, 0x08005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfrsub_vf", 0xfc00707f, 0x9c005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwadd_vv", 0xfc00707f, 0xc0001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwadd_vf", 0xfc00707f, 0xc0005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwadd_wv", 0xfc00707f, 0xd0001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwadd_wf", 0xfc00707f, 0xd0005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwsub_vv", 0xfc00707f, 0xc8001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwsub_vf", 0xfc00707f, 0xc8005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwsub_wv", 0xfc00707f, 0xd8001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwsub_wf", 0xfc00707f, 0xd8005057, CT_INDIVIDUAL},
    {         "r_vm",            "vfmul_vv", 0xfc00707f, 0x90001057, CT_INDIVIDUAL},
    {         "r_vm",            "vfmul_vf", 0xfc00707f, 0x90005057, CT_INDIVIDUAL},
    {         "r_vm",            "vfdiv_vv", 0xfc00707f, 0x80001057, CT_INDIVIDUAL},
    {         "r_vm",            "vfdiv_vf", 0xfc00707f, 0x80005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfrdiv_vf", 0xfc00707f, 0x84005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwmul_vv", 0xfc00707f, 0xe0001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfwmul_vf", 0xfc00707f, 0xe0005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfmacc_vv", 0xfc00707f, 0xb0001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfnmacc_vv", 0xfc00707f, 0xb4001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfnmacc_vf", 0xfc00707f, 0xb4005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfmacc_vf", 0xfc00707f, 0xb0005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfmsac_vv", 0xfc00707f, 0xb8001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfmsac_vf", 0xfc00707f, 0xb8005057, CT_INDIVIDUAL},
    {         "r_vm",          "vfnmsac_vv", 0xfc00707f, 0xbc001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfnmsac_vf", 0xfc00707f, 0xbc005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfmadd_vv", 0xfc00707f, 0xa0001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfmadd_vf", 0xfc00707f, 0xa0005057, CT_INDIVIDUAL},
    {         "r_vm",          "vfnmadd_vv", 0xfc00707f, 0xa4001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfnmadd_vf", 0xfc00707f, 0xa4005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfmsub_vv", 0xfc00707f, 0xa8001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfmsub_vf", 0xfc00707f, 0xa8005057, CT_INDIVIDUAL},
    {         "r_vm",          "vfnmsub_vv", 0xfc00707f, 0xac001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfnmsub_vf", 0xfc00707f, 0xac005057, CT_INDIVIDUAL},
    {         "r_vm",          "vfwmacc_vv", 0xfc00707f, 0xf0001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfwmacc_vf", 0xfc00707f, 0xf0005057, CT_INDIVIDUAL},
    {         "r_vm",         "vfwnmacc_vv", 0xfc00707f, 0xf4001057, CT_INDIVIDUAL},
    {         "r_vm",         "vfwnmacc_vf", 0xfc00707f, 0xf4005057, CT_INDIVIDUAL},
    {         "r_vm",          "vfwmsac_vv", 0xfc00707f, 0xf8001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfwmsac_vf", 0xfc00707f, 0xf8005057, CT_INDIVIDUAL},
    {         "r_vm",         "vfwnmsac_vv", 0xfc00707f, 0xfc001057, CT_INDIVIDUAL},
    {         "r_vm",         "vfwnmsac_vf", 0xfc00707f, 0xfc005057, CT_INDIVIDUAL},
    {        "r2_vm",            "vfsqrt_v", 0xfc0ff07f, 0x4c001057, CT_INDIVIDUAL},
    {        "r2_vm",          "vfrsqrt7_v", 0xfc0ff07f, 0x4c021057, CT_INDIVIDUAL},
    {        "r2_vm",            "vfrec7_v", 0xfc0ff07f, 0x4c029057, CT_INDIVIDUAL},
    {         "r_vm",            "vfmin_vv", 0xfc00707f, 0x10001057, CT_INDIVIDUAL},
    {         "r_vm",            "vfmin_vf", 0xfc00707f, 0x10005057, CT_INDIVIDUAL},
    {         "r_vm",            "vfmax_vv", 0xfc00707f, 0x18001057, CT_INDIVIDUAL},
    {         "r_vm",            "vfmax_vf", 0xfc00707f, 0x18005057, CT_INDIVIDUAL},
    {         "r_vm",           "vfsgnj_vv", 0xfc00707f, 0x20001057, CT_INDIVIDUAL},
    {         "r_vm",           "vfsgnj_vf", 0xfc00707f, 0x20005057, CT_INDIVIDUAL},
    {         "r_vm",          "vfsgnjn_vv", 0xfc00707f, 0x24001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfsgnjn_vf", 0xfc00707f, 0x24005057, CT_INDIVIDUAL},
    {         "r_vm",          "vfsgnjx_vv", 0xfc00707f, 0x28001057, CT_INDIVIDUAL},
    {         "r_vm",          "vfsgnjx_vf", 0xfc00707f, 0x28005057, CT_INDIVIDUAL},
    {         "r_vm",       "vfslide1up_vf", 0xfc00707f, 0x38005057, CT_INDIVIDUAL},
    {         "r_vm",     "vfslide1down_vf", 0xfc00707f, 0x3c005057, CT_INDIVIDUAL},
    {         "r_vm",            "vmfeq_vv", 0xfc00707f, 0x60001057, CT_INDIVIDUAL},
    {         "r_vm",            "vmfeq_vf", 0xfc00707f, 0x60005057, CT_INDIVIDUAL},
    {         "r_vm",            "vmfne_vv", 0xfc00707f, 0x70001057, CT_INDIVIDUAL},
    {         "r_vm",            "vmfne_vf", 0xfc00707f, 0x70005057, CT_INDIVIDUAL},
    {         "r_vm",            "vmflt_vv", 0xfc00707f, 0x6c001057, CT_INDIVIDUAL},
    {         "r_vm",            "vmflt_vf", 0xfc00707f, 0x6c005057, CT_INDIVIDUAL},
    {         "r_vm",            "vmfle_vv", 0xfc00707f, 0x64001057, CT_INDIVIDUAL},
    {         "r_vm",            "vmfle_vf", 0xfc00707f, 0x64005057, CT_INDIVIDUAL},
    {         "r_vm",            "vmfgt_vf", 0xfc00707f, 0x74005057, CT_INDIVIDUAL},
    {         "r_vm",            "vmfge_vf", 0xfc00707f, 0x7c005057, CT_INDIVIDUAL},
    {        "r2_vm",           "vfclass_v", 0xfc0ff07f, 0x4c081057, CT_INDIVIDUAL},
    {       "r_vm_0",         "vfmerge_vfm", 0xfe00707f, 0x5c005057, CT_INDIVIDUAL},
    {           "r2",            "vfmv_v_f", 0xfff0707f, 0x5e005057, CT_INDIVIDUAL},
    {        "r2_vm",        "vfcvt_xu_f_v", 0xfc0ff07f, 0x48001057, CT_INDIVIDUAL},
    {        "r2_vm",         "vfcvt_x_f_v", 0xfc0ff07f, 0x48009057, CT_INDIVIDUAL},
    {        "r2_vm",        "vfcvt_f_xu_v", 0xfc0ff07f, 0x48011057, CT_INDIVIDUAL},
    {        "r2_vm",         "vfcvt_f_x_v", 0xfc0ff07f, 0x48019057, CT_INDIVIDUAL},
    {        "r2_vm",    "vfcvt_rtz_xu_f_v", 0xfc0ff07f, 0x48031057, CT_INDIVIDUAL},
    {        "r2_vm",     "vfcvt_rtz_x_f_v", 0xfc0ff07f, 0x48039057, CT_INDIVIDUAL},
    {        "r2_vm",       "vfwcvt_xu_f_v", 0xfc0ff07f, 0x48041057, CT_INDIVIDUAL},
    {        "r2_vm",        "vfwcvt_x_f_v", 0xfc0ff07f, 0x48049057, CT_INDIVIDUAL},
    {        "r2_vm",       "vfwcvt_f_xu_v", 0xfc0ff07f, 0x48051057, CT_INDIVIDUAL},
    {        "r2_vm",        "vfwcvt_f_x_v", 0xfc0ff07f, 0x48059057, CT_INDIVIDUAL},
    {        "r2_vm",        "vfwcvt_f_f_v", 0xfc0ff07f, 0x48061057, CT_INDIVIDUAL},
    {        "r2_vm",   "vfwcvt_rtz_xu_f_v", 0xfc0ff07f, 0x48071057, CT_INDIVIDUAL},
    {        "r2_vm",    "vfwcvt_rtz_x_f_v", 0xfc0ff07f, 0x48079057, CT_INDIVIDUAL},
    {        "r2_vm",       "vfncvt_xu_f_w", 0xfc0ff07f, 0x48081057, CT_INDIVIDUAL},
    {        "r2_vm",        "vfncvt_x_f_w", 0xfc0ff07f, 0x48089057, CT_INDIVIDUAL},
    {        "r2_vm",       "vfncvt_f_xu_w", 0xfc0ff07f, 0x48091057, CT_INDIVIDUAL},
    {        "r2_vm",        "vfncvt_f_x_w", 0xfc0ff07f, 0x48099057, CT_INDIVIDUAL},
    {        "r2_vm",        "vfncvt_f_f_w", 0xfc0ff07f, 0x480a1057, CT_INDIVIDUAL},
    {        "r2_vm",    "vfncvt_rod_f_f_w", 0xfc0ff07f, 0x480a9057, CT_INDIVIDUAL},
    {        "r2_vm",   "vfncvt_rtz_xu_f_w", 0xfc0ff07f, 0x480b1057, CT_INDIVIDUAL},
    {        "r2_vm",    "vfncvt_rtz_x_f_w", 0xfc0ff07f, 0x480b9057, CT_INDIVIDUAL},
    {         "r_vm",          "vredsum_vs", 0xfc00707f, 0x00002057, CT_INDIVIDUAL},
    {         "r_vm",          "vredand_vs", 0xfc00707f, 0x04002057, CT_INDIVIDUAL},
    {         "r_vm",           "vredor_vs", 0xfc00707f, 0x08002057, CT_INDIVIDUAL},
    {         "r_vm",          "vredxor_vs", 0xfc00707f, 0x0c002057, CT_INDIVIDUAL},
    {         "r_vm",         "vredminu_vs", 0xfc00707f, 0x10002057, CT_INDIVIDUAL},
    {         "r_vm",          "vredmin_vs", 0xfc00707f, 0x14002057, CT_INDIVIDUAL},
    {         "r_vm",         "vredmaxu_vs", 0xfc00707f, 0x18002057, CT_INDIVIDUAL},
    {         "r_vm",          "vredmax_vs", 0xfc00707f, 0x1c002057, CT_INDIVIDUAL},
    {         "r_vm",        "vwredsumu_vs", 0xfc00707f, 0xc0000057, CT_INDIVIDUAL},
    {         "r_vm",         "vwredsum_vs", 0xfc00707f, 0xc4000057, CT_INDIVIDUAL},
    {         "r_vm",         "vfredsum_vs", 0xf400707f, 0x04001057, CT_INDIVIDUAL},
    {         "r_vm",         "vfredmin_vs", 0xfc00707f, 0x14001057, CT_INDIVIDUAL},
    {         "r_vm",         "vfredmax_vs", 0xfc00707f, 0x1c001057, CT_INDIVIDUAL},
    {         "r_vm",        "vfwredsum_vs", 0xf400707f, 0xc4001057, CT_INDIVIDUAL},
    {            "r",            "vmand_mm", 0xfc00707f, 0x64002057, CT_INDIVIDUAL},
    {            "r",           "vmnand_mm", 0xfc00707f, 0x74002057, CT_INDIVIDUAL},
    {            "r",           "vmandn_mm", 0xfc00707f, 0x60002057, CT_INDIVIDUAL},
    {            "r",            "vmxor_mm", 0xfc00707f, 0x6c002057, CT_INDIVIDUAL},
    {            "r",             "vmor_mm", 0xfc00707f, 0x68002057, CT_INDIVIDUAL},
    {            "r",            "vmnor_mm", 0xfc00707f, 0x78002057, CT_INDIVIDUAL},
    {            "r",            "vmorn_mm", 0xfc00707f, 0x70002057, CT_INDIVIDUAL},
    {            "r",           "vmxnor_mm", 0xfc00707f, 0x7c002057, CT_INDIVIDUAL},
    {        "r2_vm",             "vcpop_m", 0xfc0ff07f, 0x40082057, CT_INDIVIDUAL},
    {        "r2_vm",            "vfirst_m", 0xfc0ff07f, 0x4008a057, CT_INDIVIDUAL},
    {        "r2_vm",             "vmsbf_m", 0xfc0ff07f, 0x5000a057, CT_INDIVIDUAL},
    {        "r2_vm",             "vmsif_m", 0xfc0ff07f, 0x5001a057, CT_INDIVIDUAL},
    {        "r2_vm",             "vmsof_m", 0xfc0ff07f, 0x50012057, CT_INDIVIDUAL},
    {        "r2_vm",             "viota_m", 0xfc0ff07f, 0x50082057, CT_INDIVIDUAL},
    {        "r1_vm",               "vid_v", 0xfdfff07f, 0x5008a057, CT_INDIVIDUAL},
    {         "r2rd",             "vmv_x_s", 0xfe0ff07f, 0x42002057, CT_INDIVIDUAL},
    {           "r2",             "vmv_s_x", 0xfff0707f, 0x42006057, CT_INDIVIDUAL},
    {         "r2rd",            "vfmv_f_s", 0xfe0ff07f, 0x42001057, CT_INDIVIDUAL},
    {           "r2",            "vfmv_s_f", 0xfff0707f, 0x42005057, CT_INDIVIDUAL},
    {         "r_vm",         "vslideup_vx", 0xfc00707f, 0x38004057, CT_INDIVIDUAL},
    {         "r_vm",         "vslideup_vi", 0xfc00707f, 0x38003057, CT_INDIVIDUAL},
    {         "r_vm",        "vslide1up_vx", 0xfc00707f, 0x38006057, CT_INDIVIDUAL},
    {         "r_vm",       "vslidedown_vx", 0xfc00707f, 0x3c004057, CT_INDIVIDUAL},
    {         "r_vm",       "vslidedown_vi", 0xfc00707f, 0x3c003057, CT_INDIVIDUAL},
    {         "r_vm",      "vslide1down_vx", 0xfc00707f, 0x3c006057, CT_INDIVIDUAL},
    {         "r_vm",         "vrgather_vv", 0xfc00707f, 0x30000057, CT_INDIVIDUAL},
    {         "r_vm",     "vrgatherei16_vv", 0xfc00707f, 0x38000057, CT_INDIVIDUAL},
    {         "r_vm",         "vrgather_vx", 0xfc00707f, 0x30004057, CT_INDIVIDUAL},
    {         "r_vm",         "vrgather_vi", 0xfc00707f, 0x30003057, CT_INDIVIDUAL},
    {            "r",        "vcompress_vm", 0xfc00707f, 0x5c002057, CT_INDIVIDUAL},
    {         "r2rd",             "vmv1r_v", 0xfe0ff07f, 0x9e003057, CT_INDIVIDUAL},
    {         "r2rd",             "vmv2r_v", 0xfe0ff07f, 0x9e00b057, CT_INDIVIDUAL},
    {         "r2rd",             "vmv4r_v", 0xfe0ff07f, 0x9e01b057, CT_INDIVIDUAL},
    {         "r2rd",             "vmv8r_v", 0xfe0ff07f, 0x9e03b057, CT_INDIVIDUAL},
    {        "r2_vm",           "vzext_vf2", 0xfc0ff07f, 0x48032057, CT_INDIVIDUAL},
    {        "r2_vm",           "vzext_vf4", 0xfc0ff07f, 0x48022057, CT_INDIVIDUAL},
    {        "r2_vm",           "vzext_vf8", 0xfc0ff07f, 0x48012057, CT_INDIVIDUAL},
    {        "r2_vm",           "vsext_vf2", 0xfc0ff07f, 0x4803a057, CT_INDIVIDUAL},
    {        "r2_vm",           "vsext_vf4", 0xfc0ff07f, 0x4802a057, CT_INDIVIDUAL},
    {        "r2_vm",           "vsext_vf8", 0xfc0ff07f, 0x4801a057, CT_INDIVIDUAL},
    {    "r2_zimm11",             "vsetvli", 0x8000707f, 0x00007057, CT_INDIVIDUAL},
    {    "r2_zimm10",            "vsetivli", 0xc000707f, 0xc0007057, CT_INDIVIDUAL},
    {            "r",              "vsetvl", 0xfe00707f, 0x80007057, CT_INDIVIDUAL},
    {            "r",              "sh1add", 0xfe00707f, 0x20002033, CT_INDIVIDUAL},
    {            "r",              "sh2add", 0xfe00707f, 0x20004033, CT_INDIVIDUAL},
    {            "r",              "sh3add", 0xfe00707f, 0x20006033, CT_INDIVIDUAL},
    {            "r",              "add_uw", 0xfe00707f, 0x0800003b, CT_INDIVIDUAL},
    {            "r",           "sh1add_uw", 0xfe00707f, 0x2000203b, CT_INDIVIDUAL},
    {            "r",           "sh2add_uw", 0xfe00707f, 0x2000403b, CT_INDIVIDUAL},
    {            "r",           "sh3add_uw", 0xfe00707f, 0x2000603b, CT_INDIVIDUAL},
    {           "sh",             "slli_uw", 0xf800707f, 0x0800101b, CT_INDIVIDUAL},
    {            "r",                "andn", 0xfe00707f, 0x40007033, CT_INDIVIDUAL},
    {           "r2",                 "clz", 0xfff0707f, 0x60001013, CT_INDIVIDUAL},
    {           "r2",                "cpop", 0xfff0707f, 0x60201013, CT_INDIVIDUAL},
    {           "r2",                 "ctz", 0xfff0707f, 0x60101013, CT_INDIVIDUAL},
    {            "r",                 "max", 0xfe00707f, 0x0a006033, CT_INDIVIDUAL},
    {            "r",                "maxu", 0xfe00707f, 0x0a007033, CT_INDIVIDUAL},
    {            "r",                 "min", 0xfe00707f, 0x0a004033, CT_INDIVIDUAL},
    {            "r",                "minu", 0xfe00707f, 0x0a005033, CT_INDIVIDUAL},
    {           "r2",               "orc_b", 0xfff0707f, 0x28705013, CT_INDIVIDUAL},
    {            "r",                 "orn", 0xfe00707f, 0x40006033, CT_INDIVIDUAL},
    {           "r2",             "rev8_32", 0xfff0707f, 0x69805013, CT_INDIVIDUAL},
    {            "r",                 "rol", 0xfe00707f, 0x60001033, CT_INDIVIDUAL},
    {            "r",                 "ror", 0xfe00707f, 0x60005033, CT_INDIVIDUAL},
    {           "sh",                "rori", 0xf800707f, 0x60005013, CT_INDIVIDUAL},
    {           "r2",              "sext_b", 0xfff0707f, 0x60401013, CT_INDIVIDUAL},
    {           "r2",              "sext_h", 0xfff0707f, 0x60501013, CT_INDIVIDUAL},
    {            "r",                "xnor", 0xfe00707f, 0x40004033, CT_INDIVIDUAL},
    {           "r2",           "zext_h_32", 0xfff0707f, 0x08004033, CT_INDIVIDUAL},
    {           "r2",                "clzw", 0xfff0707f, 0x6000101b, CT_INDIVIDUAL},
    {           "r2",                "ctzw", 0xfff0707f, 0x6010101b, CT_INDIVIDUAL},
    {           "r2",               "cpopw", 0xfff0707f, 0x6020101b, CT_INDIVIDUAL},
    {           "r2",             "rev8_64", 0xfff0707f, 0x6b805013, CT_INDIVIDUAL},
    {            "r",                "rolw", 0xfe00707f, 0x6000103b, CT_INDIVIDUAL},
    {          "sh5",               "roriw", 0xfe00707f, 0x6000501b, CT_INDIVIDUAL},
    {            "r",                "rorw", 0xfe00707f, 0x6000503b, CT_INDIVIDUAL},
    {           "r2",           "zext_h_64", 0xfff0707f, 0x0800403b, CT_INDIVIDUAL},
    {            "r",               "clmul", 0xfe00707f, 0x0a001033, CT_INDIVIDUAL},
    {            "r",              "clmulh", 0xfe00707f, 0x0a003033, CT_INDIVIDUAL},
    {            "r",              "clmulr", 0xfe00707f, 0x0a002033, CT_INDIVIDUAL},
    {            "r",                "bclr", 0xfe00707f, 0x48001033, CT_INDIVIDUAL},
    {           "sh",               "bclri", 0xf800707f, 0x48001013, CT_INDIVIDUAL},
    {            "r",                "bext", 0xfe00707f, 0x48005033, CT_INDIVIDUAL},
    {           "sh",               "bexti", 0xf800707f, 0x48005013, CT_INDIVIDUAL},
    {            "r",                "binv", 0xfe00707f, 0x68001033, CT_INDIVIDUAL},
    {           "sh",               "binvi", 0xf800707f, 0x68001013, CT_INDIVIDUAL},
    {            "r",                "bset", 0xfe00707f, 0x28001033, CT_INDIVIDUAL},
    {           "sh",               "bseti", 0xf800707f, 0x28001013, CT_INDIVIDUAL},
    {            "i",                 "flh", 0x0000707f, 0x00001007, CT_INDIVIDUAL},
    {            "s",                 "fsh", 0x0000707f, 0x00001027, CT_INDIVIDUAL},
    {        "r4_rm",             "fmadd_h", 0x0600007f, 0x04000043, CT_INDIVIDUAL},
    {        "r4_rm",             "fmsub_h", 0x0600007f, 0x04000047, CT_INDIVIDUAL},
    {        "r4_rm",            "fnmsub_h", 0x0600007f, 0x0400004b, CT_INDIVIDUAL},
    {        "r4_rm",            "fnmadd_h", 0x0600007f, 0x0400004f, CT_INDIVIDUAL},
    {         "r_rm",              "fadd_h", 0xfe00007f, 0x04000053, CT_INDIVIDUAL},
    {         "r_rm",              "fsub_h", 0xfe00007f, 0x0c000053, CT_INDIVIDUAL},
    {         "r_rm",              "fmul_h", 0xfe00007f, 0x14000053, CT_INDIVIDUAL},
    {         "r_rm",              "fdiv_h", 0xfe00007f, 0x1c000053, CT_INDIVIDUAL},
    {        "r2_rm",             "fsqrt_h", 0xfff0007f, 0x5c000053, CT_INDIVIDUAL},
    {            "r",             "fsgnj_h", 0xfe00707f, 0x24000053, CT_INDIVIDUAL},
    {            "r",            "fsgnjn_h", 0xfe00707f, 0x24001053, CT_INDIVIDUAL},
    {            "r",            "fsgnjx_h", 0xfe00707f, 0x24002053, CT_INDIVIDUAL},
    {            "r",              "fmin_h", 0xfe00707f, 0x2c000053, CT_INDIVIDUAL},
    {            "r",              "fmax_h", 0xfe00707f, 0x2c001053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_h_s", 0xfff0007f, 0x44000053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_s_h", 0xfff0007f, 0x40200053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_h_d", 0xfff0007f, 0x44100053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_d_h", 0xfff0007f, 0x42200053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_w_h", 0xfff0007f, 0xc4000053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_wu_h", 0xfff0007f, 0xc4100053, CT_INDIVIDUAL},
    {           "r2",             "fmv_x_h", 0xfff0707f, 0xe4000053, CT_INDIVIDUAL},
    {            "r",               "feq_h", 0xfe00707f, 0xa4002053, CT_INDIVIDUAL},
    {            "r",               "flt_h", 0xfe00707f, 0xa4001053, CT_INDIVIDUAL},
    {            "r",               "fle_h", 0xfe00707f, 0xa4000053, CT_INDIVIDUAL},
    {           "r2",            "fclass_h", 0xfff0707f, 0xe4001053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_h_w", 0xfff0007f, 0xd4000053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_h_wu", 0xfff0007f, 0xd4100053, CT_INDIVIDUAL},
    {           "r2",             "fmv_h_x", 0xfff0707f, 0xf4000053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_l_h", 0xfff0007f, 0xc4200053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_lu_h", 0xfff0007f, 0xc4300053, CT_INDIVIDUAL},
    {        "r2_rm",            "fcvt_h_l", 0xfff0007f, 0xd4200053, CT_INDIVIDUAL},
    {        "r2_rm",           "fcvt_h_lu", 0xfff0007f, 0xd4300053, CT_INDIVIDUAL},
    { "Unclassified",   "unclas",   0x00000000, 0x00000000, CT_INDIVIDUAL },
};

static void freeInstInfo(gpointer data)
{
    // InstCountInfo *rec = (InstCountInfo *) data;
    // g_free(rec);
    // g_hash_table_destroy(rec->follow_insts);
}

static void count_pair_in_block(const BasicBlock* bb) {
    GQueue* insts_que = bb->insts;
    GList* iqit = g_queue_peek_head_link(insts_que);
    uint32_t pattern = GPOINTER_TO_UINT(iqit->data);
    // the first inst's info
    InstCountInfo* inst_info = g_hash_table_lookup(pattern_map, GUINT_TO_POINTER(pattern));
    inst_info->cnt += bb->exec_cnt;
    inst_cnt += bb->exec_cnt * g_queue_get_length(insts_que);
    for (iqit = iqit->next; iqit; iqit = iqit->next) {
        // follow inst's pattern
        pattern = GPOINTER_TO_UINT(iqit->data);
        uint64_t pair_cnt = (uint64_t)g_hash_table_lookup(inst_info->follow_insts, GUINT_TO_POINTER(pattern));
        if (pair_cnt != 0) {
            g_hash_table_replace(inst_info->follow_insts, GUINT_TO_POINTER(pattern), (gpointer)(pair_cnt + bb->exec_cnt));
        } else {
            g_hash_table_insert(inst_info->follow_insts, GUINT_TO_POINTER(pattern), (gpointer)bb->exec_cnt);
        }
        inst_info = g_hash_table_lookup(pattern_map, GUINT_TO_POINTER(pattern));
        inst_info->cnt += bb->exec_cnt;
    }
}

static void count_pair_across_block(void) {
    const GList* it = g_queue_peek_head_link(block_que);
    uint64_t pc = (uint64_t)it->data;
    BasicBlock* bb = (BasicBlock*) g_hash_table_lookup(block_map, (gconstpointer) pc);
    GQueue* insts_que = bb->insts;
    GList* tail = g_queue_peek_tail_link(insts_que);
    GList* head = NULL;
    uint32_t pattern = GPOINTER_TO_UINT(tail->data);
    // inst info of tail of block
    InstCountInfo* inst_info = g_hash_table_lookup(pattern_map, GUINT_TO_POINTER(pattern));
    // fprintf(stderr, "%s\n", inst_info->name);
    for (it = it -> next; it; it = it->next) {
        pc = (uint64_t)it->data;
        bb = (BasicBlock*) g_hash_table_lookup(block_map, (gconstpointer) pc);
        insts_que = bb->insts;
        head = g_queue_peek_head_link(insts_que);
        pattern = GPOINTER_TO_UINT(head->data);
        uint64_t pair_cnt = (uint64_t)g_hash_table_lookup(inst_info->follow_insts, GUINT_TO_POINTER(pattern));
        if (pair_cnt) {
            g_hash_table_replace(inst_info->follow_insts, GUINT_TO_POINTER(pattern), (gpointer)(pair_cnt + 1));
        } else {
            g_hash_table_replace(inst_info->follow_insts, GUINT_TO_POINTER(pattern), (gpointer)(1));
        }

        tail = g_queue_peek_tail_link(insts_que);
        pattern = GPOINTER_TO_UINT(tail->data);
        inst_info = g_hash_table_lookup(pattern_map, GUINT_TO_POINTER(pattern));
        // fprintf(stderr, "%s\n", inst_info->name);
    }
}

static void print_inst_pairs(void)
{
    g_autoptr(GString) report = g_string_new("print inst pairs ...\n");
    qemu_plugin_outs(report->str);
    report = g_string_set_size(report, 0);
    for (int i = 0; i < ARRAY_SIZE(riscv64_insns); i++) {
        GList* keys = g_hash_table_get_keys(riscv64_insns[i].follow_insts);
        GList* it = keys;
        if (it) {
            for (; it; it = it->next) {
                uint32_t follow_inst_pattern = GPOINTER_TO_UINT(it->data);
                uint64_t cnt = (uint64_t)g_hash_table_lookup(riscv64_insns[i].follow_insts, GUINT_TO_POINTER(follow_inst_pattern));
                InstCountInfo* follow_inst_info = g_hash_table_lookup(pattern_map, GUINT_TO_POINTER(follow_inst_pattern));
                g_string_append_printf(report, "%s-%s: %lu\n", riscv64_insns[i].name, follow_inst_info->name, cnt);
            }
            qemu_plugin_outs(report->str);
            report = g_string_set_size(report, 0);
            g_list_free(keys);
        }
    }

    qemu_plugin_outs(report->str);
}

static void print_insts(void)
{
    g_autoptr(GString) report = g_string_new("print insts ...\n");
    qemu_plugin_outs(report->str);
    report = g_string_set_size(report, 0);
    for (int i = 0; i < ARRAY_SIZE(riscv64_insns); i++) {
        if (riscv64_insns[i].cnt != 0)
            g_string_append_printf(report, "%s: %lu\n", riscv64_insns[i].name, riscv64_insns[i].cnt);
    }
    qemu_plugin_outs(report->str);
}

static void plugin_exit(qemu_plugin_id_t id, void* p)
{
    g_autoptr(GString) report = g_string_new("plugin_exit...\n");
    g_string_append_printf(report, "hash_table size: %d\n", g_hash_table_size(block_map));
    g_string_append_printf(report, "block_que size: %d\n", g_queue_get_length(block_que));
    
    GList* it = g_queue_peek_head_link(block_que);
    for (; it; it = it->next) {
        uint64_t pc = (uint64_t)it->data;
        BasicBlock* bb = (BasicBlock*) g_hash_table_lookup(block_map, (gconstpointer) pc);
        g_assert(bb);
        bb->exec_cnt++;
    }
    GList* block_it = g_hash_table_get_values(block_map);
    it = block_it;
    if (it) {
        for (; it; it = it->next) {
            const BasicBlock* bb = (BasicBlock*) it->data;
            count_pair_in_block(bb);
        }
    }
    count_pair_across_block();

    g_string_append_printf(report, "total inst cnt: %lu\n", inst_cnt);
    qemu_plugin_outs(report->str);

    print_insts();
    print_inst_pairs();

    g_hash_table_destroy(pattern_map);
    g_queue_free(block_que);
}

static void plugin_init(void)
{
    pattern_map = g_hash_table_new_full(NULL, g_direct_equal, NULL, &freeInstInfo);
    for (size_t i=0; i < ARRAY_SIZE(riscv64_insns); i++) {
        riscv64_insns[i].follow_insts = g_hash_table_new(NULL, g_direct_equal);
        g_hash_table_insert(pattern_map, GUINT_TO_POINTER(riscv64_insns[i].pattern), &riscv64_insns[i]);
    }
    block_que = g_queue_new();
    block_map = g_hash_table_new(NULL, g_direct_equal);
}

static uint32_t find_pattern(struct qemu_plugin_insn *insn)
{
    uint32_t inst = *(uint32_t*) qemu_plugin_insn_data(insn);
    uint32_t masked_bits;
    InstCountInfo* entry;

    for (size_t i = 0; i < ARRAY_SIZE(riscv64_insns); i++) {
        entry = &riscv64_insns[i];
        masked_bits = inst & entry->mask;
        if (masked_bits == entry->pattern){
            break;
        }
    }

    g_assert(entry);

    return entry->pattern;
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    BasicBlock* bb;
    uint64_t pc = (uint64_t) udata;

    // g_mutex_lock(&lock);
    bb = (BasicBlock *) g_hash_table_lookup(block_map, (gconstpointer) pc);
    /* should always succeed */
    g_assert(bb);
    
    // g_mutex_unlock(&lock);
    g_queue_push_tail(block_que, (gpointer)pc);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    BasicBlock* bb;
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n = qemu_plugin_tb_n_insns(tb);

    bb = (BasicBlock*) g_hash_table_lookup(block_map, (gconstpointer)pc);
    if (bb) {
        bb->trans_cnt++;

    } else {
        bb = g_new0(BasicBlock, 1);
        bb->start_addr = pc;
        bb->insts = g_queue_new();
        bb->trans_cnt = 1;
        for (size_t i = 0; i < n; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
            uint32_t pattern = find_pattern(insn);
            g_queue_push_tail(bb->insts, GUINT_TO_POINTER(pattern));
        }
        g_hash_table_insert(block_map, (gpointer)pc, (gpointer)bb);
    }

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                            QEMU_PLUGIN_CB_NO_REGS,
                                            (void *)pc);

}


QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id,
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
