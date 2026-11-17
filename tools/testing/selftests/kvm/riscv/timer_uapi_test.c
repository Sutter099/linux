// SPDX-License-Identifier: GPL-2.0-only
/* RISC-V timer one-reg migration constraints and per-vCPU timer state. */
#include "kvm_util.h"
#include "processor.h"

static void test_frequency(struct kvm_vcpu **vcpus)
{
	u64 id = RISCV_TIMER_REG(frequency);
	u64 frequency = vcpu_get_reg(vcpus[0], id);
	int ret;

	TEST_ASSERT(frequency, "Timer frequency must be nonzero");
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], id), frequency);
	/* Restoring the host frequency is allowed; changing it is not. */
	vcpu_set_reg(vcpus[0], id, frequency);
	ret = __vcpu_set_reg(vcpus[0], id, frequency ^ 1);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "Changing timer frequency returned %d, errno=%d", ret, errno);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], id), frequency);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], id), frequency);
}

static void test_compare_isolation(struct kvm_vcpu **vcpus)
{
	const u64 compare = RISCV_TIMER_REG(compare);
	const u64 values[] = { 0, 0x123456789abcdef0ULL, ~0ULL };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		vcpu_set_reg(vcpus[0], compare, values[i]);
		vcpu_set_reg(vcpus[1], compare, ~values[i]);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], compare), values[i]);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], compare), ~values[i]);
	}
	vcpu_set_reg(vcpus[1], compare, values[1]);
	vcpu_set_reg(vcpus[0], compare, 0);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], compare), values[1]);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], compare), 0);
}

static void test_state_roundtrip(struct kvm_vcpu **vcpus)
{
	const u64 compare = RISCV_TIMER_REG(compare);
	const u64 state = RISCV_TIMER_REG(state);
	u64 frequency = vcpu_get_reg(vcpus[0], RISCV_TIMER_REG(frequency));
	u64 now, delta, deadline;
	unsigned int v;

	/* Keep the software timers pending throughout this ioctl-only test. */
	TEST_ASSERT(frequency && frequency <= ~0ULL / 60,
		    "Invalid timer frequency: %lu", frequency);
	delta = frequency * 60;
	now = vcpu_get_reg(vcpus[0], RISCV_TIMER_REG(time));
	TEST_ASSERT(now < ~0ULL - delta, "Timer deadline would overflow");
	deadline = now + delta;
	for (v = 0; v < 2; v++) {
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[v], state), KVM_RISCV_TIMER_STATE_OFF);
		vcpu_set_reg(vcpus[v], compare, deadline + v);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[v], state), KVM_RISCV_TIMER_STATE_OFF);
	}

	/* Establish ON as a positive control before relying on OFF readback. */
	vcpu_set_reg(vcpus[0], state, KVM_RISCV_TIMER_STATE_ON);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], state), KVM_RISCV_TIMER_STATE_ON);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], state), KVM_RISCV_TIMER_STATE_OFF);
	vcpu_set_reg(vcpus[1], state, KVM_RISCV_TIMER_STATE_ON);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], state), KVM_RISCV_TIMER_STATE_ON);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], state), KVM_RISCV_TIMER_STATE_ON);

	vcpu_set_reg(vcpus[0], state, KVM_RISCV_TIMER_STATE_OFF);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], state), KVM_RISCV_TIMER_STATE_OFF);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], state), KVM_RISCV_TIMER_STATE_ON);
	vcpu_set_reg(vcpus[1], state, KVM_RISCV_TIMER_STATE_OFF);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], state), KVM_RISCV_TIMER_STATE_OFF);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], compare), deadline);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], compare), deadline + 1);
}

int main(void)
{
	const struct {
		const char *name;
		void (*run)(struct kvm_vcpu **vcpus);
		bool software_timer_only;
	} tests[] = {
		{ "timer_frequency_write_constraint", test_frequency, false },
		{ "timer_compare_vcpu_isolation", test_compare_isolation, false },
		{ "timer_state_vcpu_isolation", test_state_roundtrip, true },
	};
	unsigned int i;

	ksft_print_header();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ONE_REG));
	ksft_set_plan(ARRAY_SIZE(tests));
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		struct kvm_vm *vm = vm_create_barebones();
		struct kvm_vcpu *vcpus[] = { __vm_vcpu_add(vm, 0),
					    __vm_vcpu_add(vm, 1) };

		/* Sstc state reflects the blocking hrtimer, not vstimecmp enable. */
		if (tests[i].software_timer_only &&
		    __vcpu_has_isa_ext(vcpus[0], KVM_RISCV_ISA_EXT_SSTC)) {
			ksft_test_result_skip("%s: requires software timer backend\n",
					      tests[i].name);
		} else {
			tests[i].run(vcpus);
			ksft_test_result_pass("%s\n", tests[i].name);
		}
		kvm_vm_free(vm);
	}
	ksft_finished();
}
