# Data Race Vulnerability Reproduction (syzbot-a834b993)

This project adds how to reproduce the **data race vulnerability** reported by syzbot (**ID: syzbot-a834b993**). Since syzbot did not provide a working PoC, this repository collects the necessary materials and steps to reproduce the vulnerability.

---

## 📌 Materials

1. **Kernel Version**  
   The first kernel version referenced by syzbot:  
   Branch/commit: `7bf70dbb18820b37406fdfa2aaf14c2f5c71a11a`

2. **Kernel Patch**  
   See [`af_netlink.patch`](./af_netlink.patch), which introduces artificial delays into `af_netlink.c` to increase the chance of triggering the race.

3. **Kernel Config**  
   Kernel configuration file: [`kernel-config`](./kernel-config).

4. **Compiler**  
   The kernel is built with **clang-13**.

5. **Runtime Environment**  
   The target kernel runs under **QEMU**; see [`run.sh`](./run.sh) for details.

6. **Initialization Script**  
   After the kernel is booted, run [`init.sh`](./init.sh) to set up the environment.

7. **Proof-of-Concept**  
   The PoC source code is provided in [`data_race_v18.c`](./data_race_v18.c).

---

