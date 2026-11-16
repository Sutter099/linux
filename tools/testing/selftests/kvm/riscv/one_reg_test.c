// SPDX-License-Identifier: GPL-2.0-only
/* Exercise RISC-V one-reg values, validation, and vCPU-local state. */
#include <sys/mman.h>

#include "kvm_util.h"
#include "processor.h"
#include "sbi.h"
#include "ucall_common.h"

#define REG_SENTINEL 0xa5a55a5af00f0ff0ULL

static const unsigned long csr_indices[] = {
	KVM_REG_RISCV_CSR_REG(stvec),
	KVM_REG_RISCV_CSR_REG(sscratch),
	KVM_REG_RISCV_CSR_REG(sepc),
	KVM_REG_RISCV_CSR_REG(scause),
	KVM_REG_RISCV_CSR_REG(stval),
};

static u64 csr_reg(unsigned int index)
{
	return __kvm_reg_id(KVM_REG_RISCV_CSR, KVM_REG_RISCV_CSR_GENERAL,
			    csr_indices[index], KVM_REG_SIZE_ULONG);
}

static void assert_set_errno(struct kvm_vcpu *vcpu, u64 id, u64 value,
			     int expected)
{
	int ret = __vcpu_set_reg(vcpu, id, value);

	TEST_ASSERT(ret == -1 && errno == expected,
		    "SET_ONE_REG id=%#lx returned %d, errno=%d, expected %d",
		    id, ret, errno, expected);
}

static void assert_get_errno(struct kvm_vcpu *vcpu, u64 id, int expected)
{
	u64 value = REG_SENTINEL;
	int ret = __vcpu_get_reg(vcpu, id, &value);

	TEST_ASSERT(ret == -1 && errno == expected,
		    "GET_ONE_REG id=%#lx returned %d, errno=%d, expected %d",
		    id, ret, errno, expected);
	TEST_ASSERT_EQ(value, REG_SENTINEL);
}

static u64 core_reg(unsigned int index)
{
	return __kvm_reg_id(KVM_REG_RISCV_CORE, 0, index, KVM_REG_SIZE_ULONG);
}

static u64 pattern(unsigned int index, unsigned int pass)
{
	return (0x0123456789abcdefULL * (index + 1)) ^
	       (pass ? ~0ULL : 0);
}

static void test_core_roundtrip(struct kvm_vcpu **vcpus)
{
	unsigned int pass, i;

	/* Do not run these arbitrary PCs and stack pointers in a guest. */
	for (pass = 0; pass < 2; pass++) {
		for (i = KVM_REG_RISCV_CORE_REG(regs.pc);
		     i <= KVM_REG_RISCV_CORE_REG(regs.t6); i++)
			vcpu_set_reg(vcpus[0], core_reg(i), pattern(i, pass));
		/* Read after writing the entire bank to detect register aliasing. */
		for (i = KVM_REG_RISCV_CORE_REG(regs.pc);
		     i <= KVM_REG_RISCV_CORE_REG(regs.t6); i++)
			TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], core_reg(i)),
				       pattern(i, pass));
	}
}

static void test_csr_roundtrip(struct kvm_vcpu **vcpus)
{
	unsigned int pass, i;

	/* These CSRs have full-width backing storage in the one-reg ABI. */
	for (pass = 0; pass < 2; pass++) {
		for (i = 0; i < ARRAY_SIZE(csr_indices); i++)
			vcpu_set_reg(vcpus[0], csr_reg(i), pattern(i, pass));
		for (i = 0; i < ARRAY_SIZE(csr_indices); i++)
			TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], csr_reg(i)),
				       pattern(i, pass));
	}
}

static void test_pc_sepc_independent(struct kvm_vcpu **vcpus)
{
	struct kvm_vcpu *vcpu = vcpus[0];
	u64 pc = RISCV_CORE_REG(regs.pc);
	u64 sepc = RISCV_GENERAL_CSR_REG(sepc);

	/* The execution PC and the guest's trap-return PC are distinct. */
	vcpu_set_reg(vcpu, pc, 0x12345678);
	vcpu_set_reg(vcpu, sepc, 0x87654320);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, pc), 0x12345678);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, sepc), 0x87654320);
	vcpu_set_reg(vcpu, pc, 0);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, sepc), 0x87654320);
	vcpu_set_reg(vcpu, sepc, 0);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, pc), 0);
}

static void test_vcpu_isolation(struct kvm_vcpu **vcpus)
{
	unsigned int i, v;

	for (v = 0; v < 2; v++) {
		for (i = 0; i <= KVM_REG_RISCV_CORE_REG(regs.t6); i++)
			vcpu_set_reg(vcpus[v], core_reg(i), pattern(i, v));
		for (i = 0; i < ARRAY_SIZE(csr_indices); i++)
			vcpu_set_reg(vcpus[v], csr_reg(i), pattern(i, v));
		vcpu_set_reg(vcpus[v], RISCV_CORE_REG(mode), v);
	}
	for (v = 0; v < 2; v++) {
		for (i = 0; i <= KVM_REG_RISCV_CORE_REG(regs.t6); i++)
			TEST_ASSERT_EQ(vcpu_get_reg(vcpus[v], core_reg(i)),
				       pattern(i, v));
		for (i = 0; i < ARRAY_SIZE(csr_indices); i++)
			TEST_ASSERT_EQ(vcpu_get_reg(vcpus[v], csr_reg(i)),
				       pattern(i, v));
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[v], RISCV_CORE_REG(mode)), v);
	}
	/* Rewriting one vCPU must not change the other, even for privilege. */
	vcpu_set_reg(vcpus[0], RISCV_CORE_REG(mode), KVM_RISCV_MODE_S);
	vcpu_set_reg(vcpus[1], RISCV_CORE_REG(mode), KVM_RISCV_MODE_U);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], RISCV_CORE_REG(mode)),
		       KVM_RISCV_MODE_S);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], RISCV_CORE_REG(mode)),
		       KVM_RISCV_MODE_U);
}

static void test_invalid_encodings(struct kvm_vcpu **vcpus)
{
	const u64 valid[] = {
		RISCV_CORE_REG(regs.a0), RISCV_GENERAL_CSR_REG(sscratch),
		RISCV_CONFIG_REG(mvendorid), RISCV_TIMER_REG(compare),
	};
	const u64 sizes[] = { KVM_REG_SIZE_U8, KVM_REG_SIZE_U32,
			      KVM_REG_SIZE_U128 };
	const u64 invalid[] = {
		/* First index outside the stable core bank. */
		KVM_REG_RISCV_CORE | (sizeof(struct kvm_riscv_core) / sizeof(unsigned long)),
		/* Deliberately well outside evolving config/CSR/timer banks. */
		KVM_REG_RISCV_CONFIG | 0xffff,
		KVM_REG_RISCV_CSR | KVM_REG_RISCV_CSR_GENERAL | 0xffff,
		KVM_REG_RISCV_TIMER | 0xffff,
		KVM_REG_RISCV_CSR | KVM_REG_RISCV_SUBTYPE_MASK,
		KVM_REG_RISCV_TYPE_MASK,
	};
	struct kvm_vcpu *vcpu = vcpus[0];
	u64 saved;
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(valid); i++) {
		saved = vcpu_get_reg(vcpu, valid[i]);
		for (j = 0; j < ARRAY_SIZE(sizes); j++) {
			u64 id = (valid[i] & ~KVM_REG_SIZE_MASK) | sizes[j];

			assert_get_errno(vcpu, id, EINVAL);
			assert_set_errno(vcpu, id, REG_SENTINEL, EINVAL);
			TEST_ASSERT_EQ(vcpu_get_reg(vcpu, valid[i]), saved);
		}
	}
	for (i = 0; i < ARRAY_SIZE(invalid); i++) {
		u64 id = KVM_REG_RISCV | KVM_REG_SIZE_ULONG | invalid[i];

		assert_get_errno(vcpu, id, ENOENT);
		assert_set_errno(vcpu, id, REG_SENTINEL, ENOENT);
	}
}

static void test_user_faults(struct kvm_vcpu **vcpus)
{
	const u64 ids[] = { RISCV_CORE_REG(regs.a0),
		RISCV_GENERAL_CSR_REG(sscratch), RISCV_CONFIG_REG(mvendorid),
		RISCV_TIMER_REG(compare) };
	struct kvm_vcpu *vcpu = vcpus[0];
	size_t page_size = getpagesize();
	char *buffer = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	unsigned int i;

	TEST_ASSERT(buffer != MAP_FAILED, "mmap failed");
	TEST_ASSERT(!mprotect(buffer + page_size, page_size, PROT_NONE),
		    "mprotect failed");
	for (i = 0; i < ARRAY_SIZE(ids); i++) {
		struct kvm_one_reg reg = {
			.id = ids[i], .addr = (u64)(buffer + page_size),
		};
		u64 saved = REG_SENTINEL ^ (i + 1);
		u64 replacement = ~saved;
		int ret;

		/* Nonzero state distinguishes failed writes from zero-filled input. */
		vcpu_set_reg(vcpu, ids[i], saved);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpu, ids[i]), saved);
		/* Fully inaccessible and partially accessible input/output. */
		for (unsigned int offset = 0; offset <= sizeof(u64) / 2;
		     offset += sizeof(u64) / 2) {
			reg.addr = (u64)(buffer + page_size - offset);
			ret = __vcpu_ioctl(vcpu, KVM_GET_ONE_REG, &reg);
			TEST_ASSERT(ret == -1 && errno == EFAULT,
				    "GET_ONE_REG must reject inaccessible output");
			/* GET may partially copy out; do not feed that back to SET. */
			if (offset)
				memset(buffer + page_size - offset, 0x3c, offset);
			ret = __vcpu_ioctl(vcpu, KVM_SET_ONE_REG, &reg);
			TEST_ASSERT(ret == -1 && errno == EFAULT,
				    "SET_ONE_REG must reject inaccessible input");
			TEST_ASSERT_EQ(vcpu_get_reg(vcpu, ids[i]), saved);
		}
		/* A read-only page is valid input, but not valid output. */
		memcpy(buffer, &replacement, sizeof(replacement));
		TEST_ASSERT(!mprotect(buffer, page_size, PROT_READ),
			    "mprotect failed");
		reg.addr = (u64)buffer;
		ret = __vcpu_ioctl(vcpu, KVM_GET_ONE_REG, &reg);
		TEST_ASSERT(ret == -1 && errno == EFAULT,
			    "GET_ONE_REG must reject read-only output");
		vcpu_ioctl(vcpu, KVM_SET_ONE_REG, &reg);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpu, ids[i]), replacement);
		TEST_ASSERT(!mprotect(buffer, page_size, PROT_READ | PROT_WRITE),
			    "mprotect failed");
	}
	TEST_ASSERT(!munmap(buffer, 2 * page_size), "munmap failed");
}

static void test_config_constraints(struct kvm_vcpu **vcpus)
{
	const u64 blocks[] = { RISCV_CONFIG_REG(zicbom_block_size),
		RISCV_CONFIG_REG(zicboz_block_size) };
	struct kvm_vcpu *vcpu = vcpus[0];
	u64 id = RISCV_CONFIG_REG(isa);
	u64 saved = vcpu_get_reg(vcpu, id);
	unsigned int i;

	vcpu_set_reg(vcpu, id, saved);
	assert_set_errno(vcpu, id, saved | BIT_ULL(26), EINVAL);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, id), saved);

	id = RISCV_CONFIG_REG(satp_mode);
	saved = vcpu_get_reg(vcpu, id);
	vcpu_set_reg(vcpu, id, saved);
	assert_set_errno(vcpu, id, saved ^ 1, EINVAL);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, id), saved);

	for (i = 0; i < ARRAY_SIZE(blocks); i++) {
		saved = vcpu_get_reg(vcpu, blocks[i]);
		vcpu_set_reg(vcpu, blocks[i], saved);
		/* Zero is accepted for migration, not an instruction to clear. */
		vcpu_set_reg(vcpu, blocks[i], 0);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpu, blocks[i]), saved);
		assert_set_errno(vcpu, blocks[i], ~0ULL, EINVAL);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpu, blocks[i]), saved);
	}
}

static const unsigned long id_indices[] = { KVM_REG_RISCV_CONFIG_REG(mvendorid),
	KVM_REG_RISCV_CONFIG_REG(marchid), KVM_REG_RISCV_CONFIG_REG(mimpid) };
static const unsigned long guest_ids[] = { 0x123, 0x456, 0x789 };

static u64 id_reg(unsigned int index)
{
	return __kvm_reg_id(KVM_REG_RISCV_CONFIG, 0, id_indices[index],
			    KVM_REG_SIZE_ULONG);
}

static void guest_code(void)
{
	const int fids[] = { SBI_EXT_BASE_GET_MVENDORID,
		SBI_EXT_BASE_GET_MARCHID, SBI_EXT_BASE_GET_MIMPID };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fids); i++) {
		struct sbiret ret = sbi_ecall(SBI_EXT_BASE, fids[i], 0, 0, 0, 0, 0, 0);

		GUEST_ASSERT_EQ(ret.error, 0);
		GUEST_ASSERT_EQ(ret.value, guest_ids[i]);
	}
	GUEST_DONE();
}

static void test_config_id_lifecycle(void)
{
	struct kvm_vcpu *vcpu, *sibling;
	struct kvm_vm *vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	struct ucall uc;
	u64 sibling_ids[ARRAY_SIZE(id_indices)];
	unsigned int i;

	sibling = __vm_vcpu_add(vm, 1);
	for (i = 0; i < ARRAY_SIZE(id_indices); i++) {
		sibling_ids[i] = vcpu_get_reg(sibling, id_reg(i));
		vcpu_set_reg(vcpu, id_reg(i), guest_ids[i]);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpu, id_reg(i)), guest_ids[i]);
		TEST_ASSERT_EQ(vcpu_get_reg(sibling, id_reg(i)), sibling_ids[i]);
	}
	vcpu_run(vcpu);
	if (get_ucall(vcpu, &uc) == UCALL_ABORT)
		REPORT_GUEST_ASSERT(uc);
	TEST_ASSERT_EQ(uc.cmd, UCALL_DONE);
	for (i = 0; i < ARRAY_SIZE(id_indices); i++) {
		/* Migration may restore an identical value after the first run. */
		vcpu_set_reg(vcpu, id_reg(i), guest_ids[i]);
		assert_set_errno(vcpu, id_reg(i), guest_ids[i] ^ 1, EBUSY);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpu, id_reg(i)), guest_ids[i]);
		/* The never-run sibling remains writable. */
		vcpu_set_reg(sibling, id_reg(i), guest_ids[i] ^ 1);
		TEST_ASSERT_EQ(vcpu_get_reg(sibling, id_reg(i)), guest_ids[i] ^ 1);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpu, id_reg(i)), guest_ids[i]);
	}
	kvm_vm_free(vm);
}

int main(void)
{
	const struct {
		const char *name;
		void (*run)(struct kvm_vcpu **vcpus);
	} tests[] = {
		{ "core_register_roundtrip", test_core_roundtrip },
		{ "csr_register_roundtrip", test_csr_roundtrip },
		{ "pc_sepc_independent", test_pc_sepc_independent },
		{ "vcpu_register_isolation", test_vcpu_isolation },
		{ "invalid_register_encodings", test_invalid_encodings },
		{ "inaccessible_user_buffers", test_user_faults },
		{ "config_write_constraints", test_config_constraints },
	};
	unsigned int i;

	ksft_print_header();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ONE_REG));
	ksft_set_plan(ARRAY_SIZE(tests) + 1);
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		struct kvm_vm *vm = vm_create_barebones();
		struct kvm_vcpu *vcpus[] = { __vm_vcpu_add(vm, 0),
					    __vm_vcpu_add(vm, 1) };

		tests[i].run(vcpus);
		kvm_vm_free(vm);
		ksft_test_result_pass("%s\n", tests[i].name);
	}
	test_config_id_lifecycle();
	ksft_test_result_pass("config_id_lifecycle\n");
	ksft_finished();
}
