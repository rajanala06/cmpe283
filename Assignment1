/*  
 *  cmpe283-1.c - Kernel module for CMPE283 assignment 1
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <asm/msr.h>

#define MAX_MSG 80

/*
 * Model specific registers (MSRs) by the module.
 * See SDM volume 4, section 2.1
 */
#define IA32_VMX_BASIC          0x480

/*
 * if true VMX not supported
 */
#define IA32_VMX_PINBASED_CTLS	0x481
#define IA32_VMX_PROCBASED_CTLS	0x482
#define IA32_VMX_PROCBASED_CTLS2 0x48B
#define IA32_VMX_EXIT_CTLS	0x483
#define IA32_VMX_ENTRY_CTLS	0x484

/*
 * if true VMX supported
 */
#define IA32_VMX_TRUE_PINBASED_CTLS	0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS	0x48E
#define IA32_VMX_TRUE_EXIT_CTLS	        0x48F
#define IA32_VMX_TRUE_ENTRY_CTLS	0x490

/*
 * entry number for each control field
 */
#define NUM_PINBASED_CTLS   5
#define NUM_PROCBASED_CTLS  21
#define NUM_EXIT_CTLS       11
#define NUM_ENTRY_CTLS      9


/*
 * struct caapability_info
 *
 * Represents a single capability (bit number and description).
 * Used by report_capability to output VMX capabilities.
 */
struct capability_info {
	uint8_t bit;
	const char *name;
};

/*
 * Basic VMX capabilities
 * See SDM volume 3, section A.1
 */
struct capability_info basicvmx[1] =
{
    {23, "True VMX"}//bit 55--> bit 23 of hi.
};

/*
 * Pinbased capabilities
 * See SDM volume 3, section 24.6.1
 */
struct capability_info pinbased[NUM_PINBASED_CTLS] =
{
	{ 0, "External Interrupt Exiting" },
	{ 3, "NMI Exiting" },
	{ 5, "Virtual NMIs" },
	{ 6, "Activate VMX Preemption Timer" },
	{ 7, "Process Posted Interrupts" }
};

/*
 * Primary Procbased capabilities
 * See SDM volume 3, section 24.6.2
 */
struct capability_info procbased[NUM_PROCBASED_CTLS] =
{
    {2, "Interrupt Window Exiting"},
    {3, "Use TSC Offsetting"},
    {7, "HLT Exiting"},
    {9, "INVLPG Exiting"},
    {10, "MWAIT Exiting"},
    {11, "RDPMC Exiting"},
    {12, "RDTSC Exiting"},
    {15, "CR3 Load Exiting"},
    {16, "CR3 Store Exiting"},
    {19, "CR8 Load Exiting"},
    {20, "CR8 Store Exiting"},
    {21, "Use TPR Shadow"},
    {22, "NMI Window Exiting"},
    {23, "MOV-DR Exiting"},
    {24, "Unconditional IO Exiting"},
    {25, "Use IO Bitmaps"},
    {27, "Monitor Trap Flag"},
    {28, "Use MSR Bitmaps"},
    {29, "Monitor Exiting"},
    {30, "PAUSE Exiting"},
    {31, "Activate Secondary Controls"}
};


/*
 * Secondary Procbased capabilities
 * See SDM volume 3, section 24.6.2
 */
struct capability_info procbased2[24] =
{
    {0, "Virtualize APIC Access"},
    {1, "Enable EPT"},
    {2, "Descriptor-table Exiting"},
    {3, "Enable RDTSCP"},
    {4, "Virtualize x2APIC Mode"},
    {5, "Enable VPID"},
    {6, "WBIVD Exiting"},
    {7, "Unrestricted Guest"},
    {8, "APIC-register Virtualization"},
    {9, "Virtual-interrupt Delivery"},
    {10, "PAUSE-loop Exiting"},
    {11, "RDRAND Exiting"},
    {12, "Enable INVPCID"},
    {13, "Enable VM Functions"},
    {14, "VMCS Shadowing"},
    {15, "Enable ENCLS Exiting"},
    {16, "RDSEED Exiting"},
    {17, "Enable PML"},
    {18, "EPT-violation #VE"},
    {19, "Conceal VMC from PT"},
    {20, "Enable XSAVES or XRSTORS"},
    {22, "Mode-based Execute Control for EPT"},
    {25, "Use TSC Scaling"},
    {28, "Enable ENCLV Exiting"}
};

/*
 * VM Exit control fields capabilities
 * See SDM volume 3, section 24.7.1
 */
struct capability_info exitctl[NUM_EXIT_CTLS] =
{
    {2, "Save Debug Controls"},
    {9, "Host Addr-space Size"},
    {12, "Load IA32_PERF_GLOBAL_CTRL"},
    {15, "Acknowledge Interrupt on Exit"},
    {18, "Save IA32_PAT"},
    {19, "Load IA32_PAT"},
    {20, "Save IA32_EFER"},
    {21, "Load IA32_EFER"},
    {22, "Save VMX preemption Timer Value"},
    {23, "Clear IA32_BNDCFGS"},
    {24, "Conceal VMX from PT"}
};

/*
 * VM Entry control fields capabilities
 * See SDM volume 3, section 24.8.1
 */
struct capability_info entryctl[NUM_ENTRY_CTLS] =
{
    {2, "Load Debug Controls"},
    {9, "IA-32e Mode Guest"},
    {10, "Entry to SMM"},
    {11, "Deactivate Dual-monitor Treatment"},
    {13, "Load IA32_RERF_GLOBAL_CTRL"},
    {14, "Load IA32_PAT"},
    {15, "Load IA32_EFER"},
    {16, "Load IA32_BNDCFGS"},
    {17, "Conceal VMX from PT"}
};

/*
 * report_capability
 *
 * Reports capabilities present in 'cap' using the corresponding MSR values
 * provided in 'lo' and 'hi'.
 *
 * Parameters:
 *  cap: capability_info structure for this feature
 *  len: number of entries in 'cap'
 *  lo: low 32 bits of capability MSR value describing this feature
 *  hi: high 32 bits of capability MSR value describing this feature
 */
void
report_capability(struct capability_info *cap, uint8_t len, uint32_t lo,
    uint32_t hi)
{
	uint8_t i;
	struct capability_info *c;
	char msg[MAX_MSG];

	memset(msg, 0, sizeof(msg));
        snprintf(msg, MAX_MSG-1, "can_set | can_clear | feature \n");
        printk(msg);

	for (i = 0; i < len; i++) {
		c = &cap[i];
		snprintf(msg, MAX_MSG-1, "   %s    |    %s      | %s\n",
		    (hi & (1 << c->bit)) ? "Y" : "N",
		    !(lo & (1 << c->bit)) ? "Y" : "N",
		    c->name);
		printk(msg);
	}
}

/*
 * detect_vmx_features
 *
 * Detects and prints VMX capabilities of this host's CPU.
 */
void
detect_vmx_features(void)
{
	uint32_t lo, hi;

        /*determine if true controls are available*/
        rdmsr(IA32_VMX_BASIC, lo, hi);
        if( hi & (1<<basicvmx[0].bit) ) //true vmx supported
        {
            pr_info("CPU Support True VMX Feature: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32) );

            /* Pinbased controls */
            rdmsr(IA32_VMX_TRUE_PINBASED_CTLS, lo, hi);
            pr_info("Pinbased Controls MSR: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32));
            report_capability(pinbased, NUM_PINBASED_CTLS, lo, hi);

            /* Procbased controls */
            rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS, lo, hi);
            pr_info("Procbased Controls MSR: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32));
            report_capability(procbased, NUM_PROCBASED_CTLS, lo, hi);

            /* Exit controls */
            rdmsr(IA32_VMX_TRUE_EXIT_CTLS, lo, hi);
            pr_info("Exit Controls MSR: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32));
            report_capability(exitctl, NUM_EXIT_CTLS, lo, hi);

            /* Entry controls */
            rdmsr(IA32_VMX_TRUE_ENTRY_CTLS, lo, hi);
            pr_info("Entry Controls MSR: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32));
            report_capability(entryctl, NUM_ENTRY_CTLS, lo, hi);
        } 
        else 
        {
            pr_info("CPU NOT Support True VMX Feature: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32) );

            /* Pinbased controls */
            rdmsr(IA32_VMX_PINBASED_CTLS, lo, hi);
            pr_info("Pinbased Controls MSR: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32));
            report_capability(pinbased, NUM_PINBASED_CTLS, lo, hi);

            /* Procbased controls */
            rdmsr(IA32_VMX_PROCBASED_CTLS, lo, hi);
            pr_info("Procbased Controls MSR: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32));
            report_capability(procbased, NUM_PROCBASED_CTLS, lo, hi);

            /* Exit controls */
            rdmsr(IA32_VMX_EXIT_CTLS, lo, hi);
            pr_info("Exit Controls MSR: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32));
            report_capability(exitctl, NUM_EXIT_CTLS, lo, hi);

            /* Entry controls */
            rdmsr(IA32_VMX_ENTRY_CTLS, lo, hi);
            pr_info("Entry Controls MSR: 0x%llx\n",
                    (uint64_t)(lo | (uint64_t)hi << 32));
            report_capability(entryctl, NUM_ENTRY_CTLS, lo, hi);

        }
}

/*
 * init_module
 *
 * Module entry point
 *
 * Return Values:
 *  Always 0
 */
int
init_module(void)
{
	printk(KERN_INFO "CMPE 283 Assignment 1 Module Start\n");

	detect_vmx_features();

	/* 
	 * A non 0 return means init_module failed; module can't be loaded. 
	 */
	return 0;
}

/*
 * cleanup_module
 *
 * Function called on module unload
 */
void
cleanup_module(void)
{
	printk(KERN_INFO "CMPE 283 Assignment 1 Module Exits\n");
}
