# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from typing import List, Optional

from shared.mem_layout import get_memory_layout

from .csr import CSRFile
from .dmem import Dmem
from .err_bits import BAD_INSN_ADDR
from .ext_regs import OTBNExtRegs
from .flags import FlagReg
from .gpr import GPRs
from .loop import LoopStack
from .reg import RegFile
from .trace import Trace, TracePC
from .wsr import WSRFile


class OTBNState:
    def __init__(self) -> None:
        self.gprs = GPRs()
        self.wdrs = RegFile('w', 256, 32)

        self.wsrs = WSRFile()
        self.csrs = CSRFile()

        self.pc = 0
        self.pc_next = None  # type: Optional[int]

        self.start_addr = None  # type: Optional[int]

        _, imem_size = get_memory_layout()['IMEM']
        self.imem_size = imem_size

        self.dmem = Dmem()

        # Stalling support: Instructions can indicate they should stall by
        # returning false from OTBNInsn.pre_execute. For non instruction related
        # stalls setting self.non_insn_stall will produce a stall.
        #
        # As a special case, we stall until the URND reseed is completed then
        # stall for one more cycle before fetching the first instruction (to
        # match the behaviour of the RTL). This is modelled by setting
        # self._start_stall, self._urnd_stall and self.non_insn_stall
        self.non_insn_stall = False
        self._start_stall = False
        self._urnd_stall = False

        self.loop_stack = LoopStack()
        self.ext_regs = OTBNExtRegs()
        self.running = False

        self._err_bits = 0
        self.pending_halt = False

        self._new_rnd_data = None  # type: Optional[int]
        self._urnd_reseed_complete = False

    def set_rnd_data(self, rnd_data: int) -> None:
        self._new_rnd_data = rnd_data

    def set_urnd_reseed_complete(self) -> None:
        self._urnd_reseed_complete = True

    def loop_start(self, iterations: int, bodysize: int) -> None:
        next_pc = int(self.pc) + 4
        self.loop_stack.start_loop(next_pc, iterations, bodysize)

    def loop_step(self) -> None:
        back_pc = self.loop_stack.step(self.pc + 4)
        if back_pc is not None:
            self.pc_next = back_pc

    def changes(self) -> List[Trace]:
        c = []  # type: List[Trace]
        c += self.gprs.changes()
        if self.pc_next is not None:
            c.append(TracePC(self.pc_next))
        c += self.dmem.changes()
        c += self.loop_stack.changes()
        c += self.ext_regs.changes()
        c += self.wsrs.changes()
        c += self.csrs.flags.changes()
        c += self.wdrs.changes()
        return c

    def commit(self, sim_stalled: bool) -> None:
        # If the pending_halt flag is set or there are error bits (which should
        # imply pending_halt is set), we shouldn't get as far as commit.
        assert not self.pending_halt
        assert self._err_bits == 0

        if self._new_rnd_data:
            self.wsrs.RND.set_unsigned(self._new_rnd_data)
            self._new_rnd_data = None

        if self._urnd_stall:
            if self._urnd_reseed_complete:
                self._urnd_stall = False

            return

        # If self._start_stall, this is the end of the stall cycle at the start
        # of a run. Clear self.non_insn_stall and self._start_stall
        # and commit self.ext_regs (so the start flag becomes visible).
        if self._start_stall:
            self._start_stall = False
            self.non_insn_stall = False
            self.ext_regs.commit()

        self.dmem.commit(sim_stalled)

        # If we're stalled, there's nothing more to do: we only commit when we
        # finish our stall cycles.
        if sim_stalled:
            return

        self.gprs.commit()
        self.pc = self.pc_next if self.pc_next is not None else self.pc + 4
        self.pc_next = None
        self.loop_stack.commit()
        self.ext_regs.commit()
        self.wsrs.commit()
        self.csrs.flags.commit()
        self.wdrs.commit()

    def _abort(self) -> None:
        '''Abort any pending state changes'''
        self.gprs.abort()
        self.pc_next = None
        self.dmem.abort()
        self.loop_stack.abort()
        self.ext_regs.abort()
        self.wsrs.abort()
        self.csrs.flags.abort()
        self.wdrs.abort()

    def start(self, addr: int) -> None:
        '''Set the running flag and the ext_reg busy flag; perform state init'''
        self.ext_regs.set_bits('STATUS', 1 << 0)
        self.running = True
        self._start_stall = True
        self._urnd_stall = True
        self.non_insn_stall = True
        self.pending_halt = False
        self._err_bits = 0
        self._urnd_reseed_complete = False

        self.pc = addr
        self.start_addr = addr

        # Reset CSRs, WSRs and loop stack
        self.csrs = CSRFile()
        self.wsrs = WSRFile()
        self.loop_stack = LoopStack()

    def stop(self) -> None:
        '''Set flags to stop the processor and abort the instruction'''
        self._abort()

        # INTR_STATE is the interrupt state register. Bit 0 (which is being
        # set) is the 'done' flag.
        self.ext_regs.set_bits('INTR_STATE', 1 << 0)
        # STATUS is a status register. Bit 0 (being cleared) is the 'busy' flag
        self.ext_regs.clear_bits('STATUS', 1 << 0)

        self.ext_regs.write('ERR_BITS', self._err_bits, True)
        self.running = False

    def set_flags(self, fg: int, flags: FlagReg) -> None:
        '''Update flags for a flag group'''
        self.csrs.flags[fg] = flags

    def set_mlz_flags(self, fg: int, result: int) -> None:
        '''Update M, L, Z flags for a flag group using the given result'''
        self.csrs.flags[fg] = \
            FlagReg.mlz_for_result(self.csrs.flags[fg].C, result)

    def pre_insn(self, insn_affects_control: bool) -> None:
        '''Run before running an instruction'''
        self.loop_stack.check_insn(self.pc, insn_affects_control)

    def check_jump_dest(self) -> None:
        '''Check whether self.pc_next is a valid jump/branch target

        If not, generates a BadAddrError.

        '''
        if self.pc_next is None:
            return

        # The PC should always be non-negative (it's an error in the simulator
        # if that's come unstuck)
        assert 0 <= self.pc_next

        # Check the new PC is word-aligned
        if self.pc_next & 3:
            self._err_bits |= BAD_INSN_ADDR

        # Check the new PC lies in instruction memory
        if self.pc_next >= self.imem_size:
            self._err_bits |= BAD_INSN_ADDR

    def post_insn(self) -> None:
        '''Update state after running an instruction but before commit'''
        self.check_jump_dest()
        self.loop_step()
        self.gprs.post_insn()

        self._err_bits |= (self.gprs.err_bits() |
                           self.dmem.err_bits() |
                           self.loop_stack.err_bits())
        if self._err_bits:
            self.pending_halt = True

    def read_csr(self, idx: int) -> int:
        '''Read the CSR with index idx as an unsigned 32-bit number'''
        return self.csrs.read_unsigned(self.wsrs, idx)

    def write_csr(self, idx: int, value: int) -> None:
        '''Write value (an unsigned 32-bit number) to the CSR with index idx'''
        self.csrs.write_unsigned(self.wsrs, idx, value)

    def peek_call_stack(self) -> List[int]:
        '''Return the current call stack, bottom-first'''
        return self.gprs.peek_call_stack()

    def stop_at_end_of_cycle(self, err_bits: int) -> None:
        '''Tell the simulation to stop at the end of the cycle

        Any bits set in err_bits will be set in the ERR_BITS register when
        we're done.

        '''
        self._err_bits |= err_bits
        self.pending_halt = True
