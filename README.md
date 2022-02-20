
## RBO-Attack

POC codes for Spectre Prime+Probe attacks proposed in the paper "Restore Buffer Overflow Attack", ICOIN 2022. (https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9687185&isnumber=9687106)
The codes are tested by GCC-7.5 on Ubuntu 18.04.

### gem5 Setting
The POC codes are running on gem5 simulator with out-of-order cpu setting.
The evaluation environment (v20.1.0.2) is provided as a submodule.

    git submodule init
    git submodule update
    
The instuction for installation of **gem5** is [here](https://github.com/gem5/gem5).
### To compile the POC codes

    gcc -o breakundo -std=c99 spectre_breakundo.c
    gcc -o primebasic -std=c99 spectre_primebasic.c

 ### Running the POC
 

    cd gem5
    <install the gem5 simulator>
    scons build/X86/gem5.opt -j8
    
    <run POC with gem5>
    build/X86/gem5.opt \
	    configs/example/se.py \
		--cmd=../<POC executable> \
		--cpu-type=DerivO3CPU \
		--caches \
		--l2cache \
		--mem-size=8GB \
		--l1i_assoc=8 \
		--l1d_assoc=8 \
		--l2_assoc=8 \
		--l1i_size=32kB \
		--l1d_size=32kB \
		--bp-type=LTAGE

### Example of output

    Reading at malicious_x = 0xffffffffffdfe988... : T, 0x54
    0x54=’T’ score=15,7

### Author
**Jongmin Lee**

 - e-mail : flackekd@korea.ac.kr
