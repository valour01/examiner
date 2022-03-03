import json
import angr
from angr.sim_options import (
    ZERO_FILL_UNCONSTRAINED_MEMORY,
    ZERO_FILL_UNCONSTRAINED_REGISTERS,
)
import claripy
import atexit
from tqdm import tqdm
from .utils import bin2bytes, hex2bytes


def set_nzcv(state: angr.SimState, nzcv):
    state.regs.flags = nzcv << 28


def init_context(state: angr.SimState):
    state.options.add(ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.regs.sp = 0
    state.regs.lr = 0


def collect_context(state: angr.SimState):
    regs = []
    if state.arch.name == "ARMEL":
        for i in range(0, 16):
            reg = state.solver.eval(state.regs.get(f"r{i}"))
            regs.append(reg)
        regs.append(state.solver.eval(state.regs.flags))
    elif state.arch.name == "AARCH64":
        for i in range(0, 31):
            reg = state.solver.eval(state.regs.get(f"x{i}"))
            regs.append(reg)
        regs.append(state.solver.eval(state.regs.sp))
        regs.append(state.solver.eval(state.regs.pc))
        regs.append(0)
    return regs


def run(insts, mode, segments, entry, outfile):
    results = {}
    errors = {
        "SimIRSBNoDecodeError": 0,
        "UnsupportedDirtyError": 0,
        "UnsupportedIROpError": 0,
        "UnsupportedCCallError": 0,
        "SimOperationError": 0,
        "SimUnsatError": 0,
        "SimError": 0,
        "ClaripyOperationError": 0,
    }

    def save_results():
        with open(outfile, "w") as f:
            json.dump(results, f)
        print(errors)

    atexit.register(save_results)

    if mode == 'thumb':
        addr = entry + 1
    else:
        addr = entry
    for id, name, code in tqdm(insts):
        proj = angr.load_shellcode(b"\x00\x00\x00\x00", mode, load_address=entry)
        state: angr.SimState = proj.factory.call_state(addr=addr)
        init_context(state)

        for (start, _, _, data) in segments:
            state.memory.store(start, data)
        state.memory.store(entry, bin2bytes(code, mode))
        if mode != "arm64":
            set_nzcv(state, 0b1000)

        try:
            succ = state.step(num_inst=1)
            new_state = succ.successors[0]
            regs = collect_context(new_state)
            results[id] = " ".join([hex(reg)[2:] for reg in regs])
        except angr.errors.SimIRSBNoDecodeError:
            results[id] = "SimIRSBNoDecodeError"
            errors["SimIRSBNoDecodeError"] += 1
        except angr.errors.UnsupportedDirtyError:
            results[id] = "UnsupportedDirtyError"
            errors["UnsupportedDirtyError"] += 1
        except angr.errors.UnsupportedIROpError:
            results[id] = "UnsupportedIROpError"
            errors["UnsupportedIROpError"] += 1
        except angr.errors.SimOperationError:
            results[id] = "SimOperationError"
            errors["SimOperationError"] += 1
        except angr.errors.UnsupportedCCallError:
            results[id] = "UnsupportedCCallError"
            errors["UnsupportedCCallError"] += 1
        except angr.errors.SimUnsatError:
            results[id] = "SimUnsatError"
            errors["SimUnsatError"] += 1
        except claripy.errors.ClaripyOperationError:
            results[id] = "ClaripyOperationError"
            errors["ClaripyOperationError"] += 1
        except angr.errors.SimError:
            results[id] = "SimError"
            errors["SimError"] += 1


def run_one(code, mode, segments, entry):
    if mode == 'thumb':
        addr = entry + 1
    else:
        addr = entry
    proj = angr.load_shellcode(b"\x00\x00\x00\x00", mode, load_address=entry)
    state: angr.SimState = proj.factory.call_state(addr=addr)
    init_context(state)
    for (start, _, _, data) in segments:
        state.memory.store(start, data)
    state.memory.store(entry, hex2bytes(code, mode))
    if mode != "arm64":
        set_nzcv(state, 0b1000)

    regs = collect_context(state)
    result = " ".join([hex(reg)[2:] for reg in regs])
    print(result)

    succ = state.step(num_inst=1)
    new_state = succ.successors[0]
    print(len(succ.successors))

    regs = collect_context(new_state)
    result = " ".join([hex(reg)[2:] for reg in regs])
    print(result)
