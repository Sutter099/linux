// SPDX-License-Identifier: GPL-2.0-only
/* RISC-V timer one-reg migration constraints and per-vCPU compare state. */
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
	const u64 state = RISCV_TIMER_REG(state);
	const u64 values[] = { 0, 0x123456789abcdef0ULL, ~0ULL };
	unsigned int i;

	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], state), KVM_RISCV_TIMER_STATE_OFF);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], state), KVM_RISCV_TIMER_STATE_OFF);
	for (i = 0; i < ARRAY_SIZE(values); i++) {
		vcpu_set_reg(vcpus[0], compare, values[i]);
		vcpu_set_reg(vcpus[1], compare, ~values[i]);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], compare), values[i]);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], compare), ~values[i]);
		/* Restoring compare alone must not arm a stopped timer. */
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], state), KVM_RISCV_TIMER_STATE_OFF);
		TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], state), KVM_RISCV_TIMER_STATE_OFF);
	}
	/* Clearing one stopped timer's compare must leave its sibling intact. */
	vcpu_set_reg(vcpus[1], compare, values[1]);
	vcpu_set_reg(vcpus[0], compare, 0);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[1], compare), values[1]);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpus[0], compare), 0);
}

int main(void)
{
	const struct {
		const char *name;
		void (*run)(struct kvm_vcpu **vcpus);
	} tests[] = {
		{ "timer_frequency_write_constraint", test_frequency },
		{ "timer_compare_vcpu_isolation", test_compare_isolation },
	};
	unsigned int i;

	ksft_print_header();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ONE_REG));
	ksft_set_plan(ARRAY_SIZE(tests));
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		struct kvm_vm *vm = vm_create_barebones();
		struct kvm_vcpu *vcpus[] = { __vm_vcpu_add(vm, 0),
					    __vm_vcpu_add(vm, 1) };

		tests[i].run(vcpus);
		kvm_vm_free(vm);
		ksft_test_result_pass("%s\n", tests[i].name);
	}
	ksft_finished();
}
