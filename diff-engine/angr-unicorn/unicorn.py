import json
from tqdm import tqdm
from unicorn import Uc, UcError
from unicorn.unicorn_const import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_ERR_WRITE_PROT,
    UC_HOOK_MEM_FETCH,
    UC_HOOK_MEM_INVALID,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_VALID,
    UC_HOOK_MEM_WRITE,
    UC_MEM_FETCH_PROT,
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_READ_PROT,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_WRITE_PROT,
    UC_MEM_WRITE_UNMAPPED,
    UC_MODE_ARM,
    UC_MODE_THUMB,
    UC_MODE_LITTLE_ENDIAN,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_READ_UNMAPPED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_EXCEPTION,
    UC_ERR_INSN_INVALID,
    UC_PROT_EXEC,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
)
from unicorn import arm_const
from unicorn import arm64_const
from .utils import bin2bytes, hex2bytes


def create_emulator(mode, segments):
    if mode == "arm":
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    elif mode == "thumb":
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    elif mode == "arm64":
        mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)

    # set address mappings
    for segment in segments:
        (start, length, prot, data) = segment
        uc_prot = UC_PROT_NONE
        if prot.find("r") != -1:
            uc_prot += UC_PROT_READ
        if prot.find("w") != -1:
            uc_prot += UC_PROT_WRITE
        if prot.find("x") != -1:
            uc_prot += UC_PROT_EXEC
        mu.mem_map(start, length, uc_prot)
        mu.mem_write(start, data)

    if mode == "arm":
        mu.reg_write(arm_const.UC_ARM_REG_CPSR, 0x80000000)
    elif mode == "thumb":
        mu.reg_write(arm_const.UC_ARM_REG_CPSR, 0x00000000)
    elif mode == "arm64":
        mu.reg_write(arm64_const.UC_ARM64_REG_PSTATE, 0x80000000)

    return mu


def collect_context(mu: Uc):
    regs = []
    if mu._arch == UC_ARCH_ARM:
        for r in range(arm_const.UC_ARM_REG_R0, arm_const.UC_ARM_REG_R12 + 1):
            regs.append(mu.reg_read(r))
        regs.append(mu.reg_read(arm_const.UC_ARM_REG_SP))
        regs.append(mu.reg_read(arm_const.UC_ARM_REG_LR))
        regs.append(mu.reg_read(arm_const.UC_ARM_REG_PC))
        regs.append(mu.reg_read(arm_const.UC_ARM_REG_CPSR))
    elif mu._arch == UC_ARCH_ARM64:
        for r in range(arm64_const.UC_ARM64_REG_X0, arm64_const.UC_ARM64_REG_X28 + 1):
            regs.append(mu.reg_read(r))
        regs.append(mu.reg_read(arm64_const.UC_ARM64_REG_X29))  # UC_ARM64_REG_FP
        regs.append(mu.reg_read(arm64_const.UC_ARM64_REG_X30))  # UC_ARM64_REG_LR
        regs.append(mu.reg_read(arm64_const.UC_ARM64_REG_SP))
        regs.append(mu.reg_read(arm64_const.UC_ARM64_REG_PC))
        regs.append(mu.reg_read(arm64_const.UC_ARM64_REG_PSTATE))
    return regs


def hook_mem_invalid(uc, access, address, size, value, user_data):
    print('hook_mem_invalid')
    if access == UC_MEM_READ_UNMAPPED:
        print("read unmapped")
    elif access == UC_MEM_WRITE_UNMAPPED:
        print("write unmapped")
    elif access == UC_MEM_FETCH_UNMAPPED:
        print("fetch unmapped")
    elif access == UC_MEM_READ_PROT:
        print("read prot")
    elif access == UC_MEM_WRITE_PROT:
        print("write prot")
    elif access == UC_MEM_FETCH_PROT:
        print("fetch prot")
    else:
        print(access)
    print(hex(address), size, value)


def hook_mem_valid(uc, access, address, size, value, user_data):
    print('hook_mem_valid')
    if access == UC_HOOK_MEM_READ:
        print("read")
    elif access == UC_HOOK_MEM_WRITE:
        print("write")
    elif access == UC_HOOK_MEM_FETCH:
        print("fetch")
    else:
        print(access)
    print(hex(address), size, value)


def run_one(code, mode, segments, entry):
    mu = create_emulator(mode, segments)
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    mu.hook_add(UC_HOOK_MEM_VALID, hook_mem_valid)
    regs = collect_context(mu)
    print([hex(reg) for reg in regs])
    print(hex(entry))
    if mode == 'thumb':
        addr = entry + 1
    else:
        addr = entry
    mu.mem_write(entry, hex2bytes(code, mode))
    mu.emu_start(addr, addr + 4, count=1)
    regs = collect_context(mu)
    print([hex(reg) for reg in regs])


def run(insts, mode, segments, entry, outfile):
    mu = create_emulator(mode, segments)
    context = mu.context_save()
    results = []
    special = {
        "fetch": 0,
        "exception": 0,
    }
    special_inst = {
        "fetch": set(),
        "exception": set(),
    }
    if mode == 'thumb':
        addr = entry + 1
    else:
        addr = entry
    for id, name, code in tqdm(insts):
        mu.context_restore(context)
        mu.mem_write(entry, bin2bytes(code, mode))

        signal = None
        try:
            mu.emu_start(addr, addr + 4, count=1)
            signal = "5"
        except UcError as err:
            if err.errno == UC_ERR_INSN_INVALID:
                signal = "4"
            elif err.errno in (
                UC_ERR_READ_UNMAPPED,
                UC_ERR_WRITE_UNMAPPED,
                UC_ERR_WRITE_PROT,
            ):
                signal = "11"
            elif err.errno in (UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNMAPPED):
                special["fetch"] += 1
                special_inst["fetch"].add(name)
                pass
            elif err.errno == UC_ERR_EXCEPTION:  # inst: svc bkpt, 需要操作系统支持
                special["exception"] += 1
                special_inst["exception"].add(name)
                pass
            else:
                raise err
        finally:
            if not signal:
                results.append("")
            else:
                regs = collect_context(mu)
                result = signal + "@" + " ".join([hex(r)[2:] for r in regs]) + "$"
                results.append(result)
    with open(outfile, "w") as f:
        json.dump(results, f, indent=0)
