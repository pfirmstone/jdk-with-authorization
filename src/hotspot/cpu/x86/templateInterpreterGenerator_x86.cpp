/*
 * Copyright (c) 2003, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include "asm/macroAssembler.hpp"
#include "classfile/javaClasses.hpp"
#include "compiler/compiler_globals.hpp"
#include "compiler/disassembler.hpp"
#include "gc/shared/barrierSetAssembler.hpp"
#include "interpreter/bytecodeHistogram.hpp"
#include "interpreter/interp_masm.hpp"
#include "interpreter/interpreter.hpp"
#include "interpreter/interpreterRuntime.hpp"
#include "interpreter/templateInterpreterGenerator.hpp"
#include "interpreter/templateTable.hpp"
#include "oops/arrayOop.hpp"
#include "oops/methodCounters.hpp"
#include "oops/methodData.hpp"
#include "oops/method.hpp"
#include "oops/oop.inline.hpp"
#include "oops/resolvedIndyEntry.hpp"
#include "oops/resolvedMethodEntry.hpp"
#include "prims/jvmtiExport.hpp"
#include "prims/jvmtiThreadState.hpp"
#include "runtime/continuation.hpp"
#include "runtime/deoptimization.hpp"
#include "runtime/frame.inline.hpp"
#include "runtime/globals.hpp"
#include "runtime/jniHandles.hpp"
#include "runtime/sharedRuntime.hpp"
#include "runtime/stubRoutines.hpp"
#include "runtime/synchronizer.hpp"
#include "runtime/timer.hpp"
#include "runtime/vframeArray.hpp"
#include "utilities/checkedCast.hpp"
#include "utilities/debug.hpp"
#include "utilities/macros.hpp"

#define __ Disassembler::hook<InterpreterMacroAssembler>(__FILE__, __LINE__, _masm)->

// Size of interpreter code.  Increase if too small.  Interpreter will
// fail with a guarantee ("not enough space for interpreter generation");
// if too small.
// Run with +PrintInterpreter to get the VM to print out the size.
// Max size with JVMTI
int TemplateInterpreter::InterpreterCodeSize = JVMCI_ONLY(268) NOT_JVMCI(256) * 1024;

// Global Register Names
static const Register rbcp     = r13;
static const Register rlocals  = r14;

const int method_offset = frame::interpreter_frame_method_offset * wordSize;
const int bcp_offset    = frame::interpreter_frame_bcp_offset    * wordSize;
const int locals_offset = frame::interpreter_frame_locals_offset * wordSize;


//-----------------------------------------------------------------------------

address TemplateInterpreterGenerator::generate_StackOverflowError_handler() {
  address entry = __ pc();

#ifdef ASSERT
  {
    Label L;
    __ movptr(rax, Address(rbp,
                           frame::interpreter_frame_monitor_block_top_offset *
                           wordSize));
    __ lea(rax, Address(rbp, rax, Address::times_ptr));
    __ cmpptr(rax, rsp); // rax = maximal rsp for current rbp (stack
                         // grows negative)
    __ jcc(Assembler::aboveEqual, L); // check if frame is complete
    __ stop ("interpreter frame not set up");
    __ bind(L);
  }
#endif // ASSERT
  // Restore bcp under the assumption that the current frame is still
  // interpreted
  __ restore_bcp();

  // expression stack must be empty before entering the VM if an
  // exception happened
  __ empty_expression_stack();
  // throw exception
  __ call_VM(noreg,
             CAST_FROM_FN_PTR(address,
                              InterpreterRuntime::throw_StackOverflowError));
  return entry;
}

address TemplateInterpreterGenerator::generate_ArrayIndexOutOfBounds_handler() {
  address entry = __ pc();
  // The expression stack must be empty before entering the VM if an
  // exception happened.
  __ empty_expression_stack();

  // Setup parameters.
  // ??? convention: expect aberrant index in register ebx/rbx.
  // Pass array to create more detailed exceptions.
  __ call_VM(noreg,
             CAST_FROM_FN_PTR(address,
                              InterpreterRuntime::
                              throw_ArrayIndexOutOfBoundsException),
             c_rarg1, rbx);
  return entry;
}

address TemplateInterpreterGenerator::generate_ClassCastException_handler() {
  address entry = __ pc();

  // object is at TOS
  __ pop(c_rarg1);

  // expression stack must be empty before entering the VM if an
  // exception happened
  __ empty_expression_stack();

  __ call_VM(noreg,
             CAST_FROM_FN_PTR(address,
                              InterpreterRuntime::
                              throw_ClassCastException),
             c_rarg1);
  return entry;
}

address TemplateInterpreterGenerator::generate_exception_handler_common(
        const char* name, const char* message, bool pass_oop) {
  assert(!pass_oop || message == nullptr, "either oop or message but not both");
  address entry = __ pc();

  if (pass_oop) {
    // object is at TOS
    __ pop(c_rarg2);
  }
  // expression stack must be empty before entering the VM if an
  // exception happened
  __ empty_expression_stack();
  // setup parameters
  __ lea(c_rarg1, ExternalAddress((address)name));
  if (pass_oop) {
    __ call_VM(rax, CAST_FROM_FN_PTR(address,
                                     InterpreterRuntime::
                                     create_klass_exception),
               c_rarg1, c_rarg2);
  } else {
    __ lea(c_rarg2, ExternalAddress((address)message));
    __ call_VM(rax,
               CAST_FROM_FN_PTR(address, InterpreterRuntime::create_exception),
               c_rarg1, c_rarg2);
  }
  // throw exception
  __ jump(RuntimeAddress(Interpreter::throw_exception_entry()));
  return entry;
}

address TemplateInterpreterGenerator::generate_return_entry_for(TosState state, int step, size_t index_size) {
  address entry = __ pc();

  // Restore stack bottom in case i2c adjusted stack
  __ movptr(rcx, Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize));
  __ lea(rsp, Address(rbp, rcx, Address::times_ptr));
  // and null it as marker that esp is now tos until next java call
  __ movptr(Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize), NULL_WORD);

  __ restore_bcp();
  __ restore_locals();

  if (state == atos) {
    Register mdp = rbx;
    Register tmp = rcx;
    __ profile_return_type(mdp, rax, tmp);
  }

  const Register cache = rbx;
  const Register index = rcx;
  if (index_size == sizeof(u4)) {
    __ load_resolved_indy_entry(cache, index);
    __ load_unsigned_short(cache, Address(cache, in_bytes(ResolvedIndyEntry::num_parameters_offset())));
    __ lea(rsp, Address(rsp, cache, Interpreter::stackElementScale()));
  } else {
    assert(index_size == sizeof(u2), "Can only be u2");
    __ load_method_entry(cache, index);
    __ load_unsigned_short(cache, Address(cache, in_bytes(ResolvedMethodEntry::num_parameters_offset())));
    __ lea(rsp, Address(rsp, cache, Interpreter::stackElementScale()));
  }

   if (JvmtiExport::can_pop_frame()) {
     __ check_and_handle_popframe(r15_thread);
   }
   if (JvmtiExport::can_force_early_return()) {
     __ check_and_handle_earlyret(r15_thread);
   }

  __ dispatch_next(state, step);

  return entry;
}


address TemplateInterpreterGenerator::generate_deopt_entry_for(TosState state, int step, address continuation) {
  address entry = __ pc();

  // null last_sp until next java call
  __ movptr(Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize), NULL_WORD);
  __ restore_bcp();
  __ restore_locals();
  const Register thread = r15_thread;
#if INCLUDE_JVMCI
  // Check if we need to take lock at entry of synchronized method.  This can
  // only occur on method entry so emit it only for vtos with step 0.
  if (EnableJVMCI && state == vtos && step == 0) {
    Label L;
    __ cmpb(Address(thread, JavaThread::pending_monitorenter_offset()), 0);
    __ jcc(Assembler::zero, L);
    // Clear flag.
    __ movb(Address(thread, JavaThread::pending_monitorenter_offset()), 0);
    // Satisfy calling convention for lock_method().
    __ get_method(rbx);
    // Take lock.
    lock_method();
    __ bind(L);
  } else {
#ifdef ASSERT
    if (EnableJVMCI) {
      Label L;
      __ cmpb(Address(r15_thread, JavaThread::pending_monitorenter_offset()), 0);
      __ jcc(Assembler::zero, L);
      __ stop("unexpected pending monitor in deopt entry");
      __ bind(L);
    }
#endif
  }
#endif
  // handle exceptions
  {
    Label L;
    __ cmpptr(Address(thread, Thread::pending_exception_offset()), NULL_WORD);
    __ jcc(Assembler::zero, L);
    __ call_VM(noreg,
               CAST_FROM_FN_PTR(address,
                                InterpreterRuntime::throw_pending_exception));
    __ should_not_reach_here();
    __ bind(L);
  }
  if (continuation == nullptr) {
    __ dispatch_next(state, step);
  } else {
    __ jump_to_entry(continuation);
  }
  return entry;
}

address TemplateInterpreterGenerator::generate_result_handler_for(
        BasicType type) {
  address entry = __ pc();
  switch (type) {
  case T_BOOLEAN: __ c2bool(rax);            break;
  case T_CHAR   : __ movzwl(rax, rax);       break;
  case T_BYTE   : __ sign_extend_byte(rax);  break;
  case T_SHORT  : __ sign_extend_short(rax); break;
  case T_INT    : /* nothing to do */        break;
  case T_LONG   : /* nothing to do */        break;
  case T_VOID   : /* nothing to do */        break;
  case T_FLOAT  : /* nothing to do */        break;
  case T_DOUBLE : /* nothing to do */        break;

  case T_OBJECT :
    // retrieve result from frame
    __ movptr(rax, Address(rbp, frame::interpreter_frame_oop_temp_offset*wordSize));
    // and verify it
    __ verify_oop(rax);
    break;
  default       : ShouldNotReachHere();
  }
  __ ret(0);                                   // return from result handler
  return entry;
}

address TemplateInterpreterGenerator::generate_safept_entry_for(
        TosState state,
        address runtime_entry) {
  address entry = __ pc();

  __ push(state);
  __ push_cont_fastpath();
  __ call_VM(noreg, runtime_entry);
  __ pop_cont_fastpath();

  __ dispatch_via(vtos, Interpreter::_normal_table.table_for(vtos));
  return entry;
}

address TemplateInterpreterGenerator::generate_cont_resume_interpreter_adapter() {
  if (!Continuations::enabled()) return nullptr;
  address start = __ pc();

  __ restore_bcp();
  __ restore_locals();

  // Get return address before adjusting rsp
  __ movptr(rax, Address(rsp, 0));

  // Restore stack bottom
  __ movptr(rcx, Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize));
  __ lea(rsp, Address(rbp, rcx, Address::times_ptr));
  // and null it as marker that esp is now tos until next java call
  __ movptr(Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize), NULL_WORD);

  __ jmp(rax);

  return start;
}


// Helpers for commoning out cases in the various type of method entries.
//


// increment invocation count & check for overflow
//
// Note: checking for negative value instead of overflow
//       so we have a 'sticky' overflow test
//
// rbx: method
// rcx: invocation counter
//
void TemplateInterpreterGenerator::generate_counter_incr(Label* overflow) {
  Label done;
  // Note: In tiered we increment either counters in Method* or in MDO depending if we're profiling or not.
  Label no_mdo;
  if (ProfileInterpreter) {
    // Are we profiling?
    __ movptr(rax, Address(rbx, Method::method_data_offset()));
    __ testptr(rax, rax);
    __ jccb(Assembler::zero, no_mdo);
    // Increment counter in the MDO
    const Address mdo_invocation_counter(rax, in_bytes(MethodData::invocation_counter_offset()) +
        in_bytes(InvocationCounter::counter_offset()));
    const Address mask(rax, in_bytes(MethodData::invoke_mask_offset()));
    __ increment_mask_and_jump(mdo_invocation_counter, mask, rcx, overflow);
    __ jmp(done);
  }
  __ bind(no_mdo);
  // Increment counter in MethodCounters
  const Address invocation_counter(rax,
      MethodCounters::invocation_counter_offset() +
      InvocationCounter::counter_offset());
  __ get_method_counters(rbx, rax, done);
  const Address mask(rax, in_bytes(MethodCounters::invoke_mask_offset()));
  __ increment_mask_and_jump(invocation_counter, mask, rcx, overflow);
  __ bind(done);
}

void TemplateInterpreterGenerator::generate_counter_overflow(Label& do_continue) {

  // Asm interpreter on entry
  // r14/rdi - locals
  // r13/rsi - bcp
  // rbx - method
  // rdx - cpool --- DOES NOT APPEAR TO BE TRUE
  // rbp - interpreter frame

  // On return (i.e. jump to entry_point) [ back to invocation of interpreter ]
  // Everything as it was on entry
  // rdx is not restored. Doesn't appear to really be set.

  // InterpreterRuntime::frequency_counter_overflow takes two
  // arguments, the first (thread) is passed by call_VM, the second
  // indicates if the counter overflow occurs at a backwards branch
  // (null bcp).  We pass zero for it.  The call returns the address
  // of the verified entry point for the method or null if the
  // compilation did not complete (either went background or bailed
  // out).
  __ movl(c_rarg1, 0);
  __ call_VM(noreg,
             CAST_FROM_FN_PTR(address,
                              InterpreterRuntime::frequency_counter_overflow),
             c_rarg1);

  __ movptr(rbx, Address(rbp, method_offset));   // restore Method*
  // Preserve invariant that r13/r14 contain bcp/locals of sender frame
  // and jump to the interpreted entry.
  __ jmp(do_continue, relocInfo::none);
}

// See if we've got enough room on the stack for locals plus overhead below
// JavaThread::stack_overflow_limit(). If not, throw a StackOverflowError
// without going through the signal handler, i.e., reserved and yellow zones
// will not be made usable. The shadow zone must suffice to handle the
// overflow.
// The expression stack grows down incrementally, so the normal guard
// page mechanism will work for that.
//
// NOTE: Since the additional locals are also always pushed (wasn't
// obvious in generate_fixed_frame) so the guard should work for them
// too.
//
// Args:
//      rdx: number of additional locals this frame needs (what we must check)
//      rbx: Method*
//
// Kills:
//      rax
void TemplateInterpreterGenerator::generate_stack_overflow_check(void) {

  // monitor entry size: see picture of stack in frame_x86.hpp
  const int entry_size = frame::interpreter_frame_monitor_size_in_bytes();

  // total overhead size: entry_size + (saved rbp through expr stack
  // bottom).  be sure to change this if you add/subtract anything
  // to/from the overhead area
  const int overhead_size =
    -(frame::interpreter_frame_initial_sp_offset * wordSize) + entry_size;

  const int page_size = (int)os::vm_page_size();

  Label after_frame_check;

  // see if the frame is greater than one page in size. If so,
  // then we need to verify there is enough stack space remaining
  // for the additional locals.
  __ cmpl(rdx, (page_size - overhead_size) / Interpreter::stackElementSize);
  __ jcc(Assembler::belowEqual, after_frame_check);

  // compute rsp as if this were going to be the last frame on
  // the stack before the red zone

  Label after_frame_check_pop;

  const Address stack_limit(r15_thread, JavaThread::stack_overflow_limit_offset());

  // locals + overhead, in bytes
  __ mov(rax, rdx);
  __ shlptr(rax, Interpreter::logStackElementSize); // Convert parameter count to bytes.
  __ addptr(rax, overhead_size);

#ifdef ASSERT
  Label limit_okay;
  // Verify that thread stack overflow limit is non-zero.
  __ cmpptr(stack_limit, NULL_WORD);
  __ jcc(Assembler::notEqual, limit_okay);
  __ stop("stack overflow limit is zero");
  __ bind(limit_okay);
#endif

  // Add locals/frame size to stack limit.
  __ addptr(rax, stack_limit);

  // Check against the current stack bottom.
  __ cmpptr(rsp, rax);

  __ jcc(Assembler::above, after_frame_check_pop);

  // Restore sender's sp as SP. This is necessary if the sender's
  // frame is an extended compiled frame (see gen_c2i_adapter())
  // and safer anyway in case of JSR292 adaptations.

  __ pop(rax); // return address must be moved if SP is changed
  __ mov(rsp, rbcp);
  __ push(rax);

  // Note: the restored frame is not necessarily interpreted.
  // Use the shared runtime version of the StackOverflowError.
  assert(SharedRuntime::throw_StackOverflowError_entry() != nullptr, "stub not yet generated");
  __ jump(RuntimeAddress(SharedRuntime::throw_StackOverflowError_entry()));
  // all done with frame size check
  __ bind(after_frame_check_pop);

  // all done with frame size check
  __ bind(after_frame_check);
}

// Allocate monitor and lock method (asm interpreter)
//
// Args:
//      rbx: Method*
//      r14/rdi: locals
//
// Kills:
//      rax
//      c_rarg0, c_rarg1, c_rarg2, c_rarg3, ...(param regs)
//      rscratch1, rscratch2 (scratch regs)
void TemplateInterpreterGenerator::lock_method() {
  // synchronize method
  const Address access_flags(rbx, Method::access_flags_offset());
  const Address monitor_block_top(
        rbp,
        frame::interpreter_frame_monitor_block_top_offset * wordSize);
  const int entry_size = frame::interpreter_frame_monitor_size_in_bytes();

#ifdef ASSERT
  {
    Label L;
    __ load_unsigned_short(rax, access_flags);
    __ testl(rax, JVM_ACC_SYNCHRONIZED);
    __ jcc(Assembler::notZero, L);
    __ stop("method doesn't need synchronization");
    __ bind(L);
  }
#endif // ASSERT

  // get synchronization object
  {
    Label done;
    __ load_unsigned_short(rax, access_flags);
    __ testl(rax, JVM_ACC_STATIC);
    // get receiver (assume this is frequent case)
    __ movptr(rax, Address(rlocals, Interpreter::local_offset_in_bytes(0)));
    __ jcc(Assembler::zero, done);
    __ load_mirror(rax, rbx, rscratch2);

#ifdef ASSERT
    {
      Label L;
      __ testptr(rax, rax);
      __ jcc(Assembler::notZero, L);
      __ stop("synchronization object is null");
      __ bind(L);
    }
#endif // ASSERT

    __ bind(done);
  }

  // add space for monitor & lock
  __ subptr(rsp, entry_size); // add space for a monitor entry
  __ subptr(monitor_block_top, entry_size / wordSize); // set new monitor block top
  // store object
  __ movptr(Address(rsp, BasicObjectLock::obj_offset()), rax);
  __ movptr(c_rarg1, rsp); // object address
  __ lock_object(c_rarg1);
}

// Generate a fixed interpreter frame. This is identical setup for
// interpreted methods and for native methods hence the shared code.
//
// Args:
//      rax: return address
//      rbx: Method*
//      r14/rdi: pointer to locals
//      r13/rsi: sender sp
//      rdx: cp cache
void TemplateInterpreterGenerator::generate_fixed_frame(bool native_call) {
  // initialize fixed part of activation frame
  __ push(rax);        // save return address
  __ enter();          // save old & set new rbp
  __ push(rbcp);        // set sender sp
  __ push(NULL_WORD); // leave last_sp as null
  __ movptr(rbcp, Address(rbx, Method::const_offset()));      // get ConstMethod*
  __ lea(rbcp, Address(rbcp, ConstMethod::codes_offset())); // get codebase
  __ push(rbx);        // save Method*
  // Get mirror and store it in the frame as GC root for this Method*
  __ load_mirror(rdx, rbx, rscratch2);
  __ push(rdx);
  if (ProfileInterpreter) {
    Label method_data_continue;
    __ movptr(rdx, Address(rbx, in_bytes(Method::method_data_offset())));
    __ testptr(rdx, rdx);
    __ jcc(Assembler::zero, method_data_continue);
    __ addptr(rdx, in_bytes(MethodData::data_offset()));
    __ bind(method_data_continue);
    __ push(rdx);      // set the mdp (method data pointer)
  } else {
    __ push(0);
  }

  __ movptr(rdx, Address(rbx, Method::const_offset()));
  __ movptr(rdx, Address(rdx, ConstMethod::constants_offset()));
  __ movptr(rdx, Address(rdx, ConstantPool::cache_offset()));
  __ push(rdx); // set constant pool cache

  __ movptr(rax, rlocals);
  __ subptr(rax, rbp);
  __ shrptr(rax, Interpreter::logStackElementSize);  // rax = rlocals - fp();
  __ push(rax); // set relativized rlocals, see frame::interpreter_frame_locals()

  if (native_call) {
    __ push(0); // no bcp
  } else {
    __ push(rbcp); // set bcp
  }
  // initialize relativized pointer to expression stack bottom
  __ push(frame::interpreter_frame_initial_sp_offset);
}

// End of helpers

// Method entry for java.lang.ref.Reference.get.
address TemplateInterpreterGenerator::generate_Reference_get_entry(void) {
  // Code: _aload_0, _getfield, _areturn
  // parameter size = 1
  //
  // The code that gets generated by this routine is split into 2 parts:
  //    1. The "intrinsified" code performing an ON_WEAK_OOP_REF load,
  //    2. The slow path - which is an expansion of the regular method entry.
  //
  // Notes:-
  // * An intrinsic is always executed, where an ON_WEAK_OOP_REF load is performed.
  // * We may jump to the slow path iff the receiver is null. If the
  //   Reference object is null then we no longer perform an ON_WEAK_OOP_REF load
  //   Thus we can use the regular method entry code to generate the NPE.
  //
  // rbx: Method*

  // r13: senderSP must preserve for slow path, set SP to it on fast path

  address entry = __ pc();

  const int referent_offset = java_lang_ref_Reference::referent_offset();

  Label slow_path;
  // rbx: method

  // Check if local 0 != null
  // If the receiver is null then it is OK to jump to the slow path.
  __ movptr(rax, Address(rsp, wordSize));

  __ testptr(rax, rax);
  __ jcc(Assembler::zero, slow_path);

  // rax: local 0
  // rbx: method (but can be used as scratch now)
  // rdx: scratch
  // rdi: scratch

  // Load the value of the referent field.
  const Address field_address(rax, referent_offset);
  __ load_heap_oop(rax, field_address, /*tmp1*/ rbx, /*tmp_thread*/ rdx, ON_WEAK_OOP_REF);

  // _areturn
  __ pop(rdi);                // get return address
  __ mov(rsp, r13);           // set sp to sender sp
  __ jmp(rdi);
  __ ret(0);

  // generate a vanilla interpreter entry as the slow path
  __ bind(slow_path);
  __ jump_to_entry(Interpreter::entry_for_kind(Interpreter::zerolocals));
  return entry;
}

void TemplateInterpreterGenerator::bang_stack_shadow_pages(bool native_call) {
  // See more discussion in stackOverflow.hpp.

  // Note that we do the banging after the frame is setup, since the exception
  // handling code expects to find a valid interpreter frame on the stack.
  // Doing the banging earlier fails if the caller frame is not an interpreter
  // frame.
  // (Also, the exception throwing code expects to unlock any synchronized
  // method receiver, so do the banging after locking the receiver.)

  const int shadow_zone_size = checked_cast<int>(StackOverflow::stack_shadow_zone_size());
  const int page_size = (int)os::vm_page_size();
  const int n_shadow_pages = shadow_zone_size / page_size;

  const Register thread = r15_thread;

#ifdef ASSERT
  Label L_good_limit;
  __ cmpptr(Address(thread, JavaThread::shadow_zone_safe_limit()), NULL_WORD);
  __ jcc(Assembler::notEqual, L_good_limit);
  __ stop("shadow zone safe limit is not initialized");
  __ bind(L_good_limit);

  Label L_good_watermark;
  __ cmpptr(Address(thread, JavaThread::shadow_zone_growth_watermark()), NULL_WORD);
  __ jcc(Assembler::notEqual, L_good_watermark);
  __ stop("shadow zone growth watermark is not initialized");
  __ bind(L_good_watermark);
#endif

  Label L_done;

  __ cmpptr(rsp, Address(thread, JavaThread::shadow_zone_growth_watermark()));
  __ jcc(Assembler::above, L_done);

  for (int p = 1; p <= n_shadow_pages; p++) {
    __ bang_stack_with_offset(p*page_size);
  }

  // Record the new watermark, but only if update is above the safe limit.
  // Otherwise, the next time around the check above would pass the safe limit.
  __ cmpptr(rsp, Address(thread, JavaThread::shadow_zone_safe_limit()));
  __ jccb(Assembler::belowEqual, L_done);
  __ movptr(Address(thread, JavaThread::shadow_zone_growth_watermark()), rsp);

  __ bind(L_done);
}

// Interpreter stub for calling a native method. (asm interpreter)
// This sets up a somewhat different looking stack for calling the
// native method than the typical interpreter frame setup.
address TemplateInterpreterGenerator::generate_native_entry(bool synchronized) {
  // determine code generation flags
  bool inc_counter  = UseCompiler || CountCompiledCalls;

  // rbx: Method*
  // rbcp: sender sp

  address entry_point = __ pc();

  const Address constMethod       (rbx, Method::const_offset());
  const Address access_flags      (rbx, Method::access_flags_offset());
  const Address size_of_parameters(rcx, ConstMethod::
                                        size_of_parameters_offset());


  // get parameter size (always needed)
  __ movptr(rcx, constMethod);
  __ load_unsigned_short(rcx, size_of_parameters);

  // native calls don't need the stack size check since they have no
  // expression stack and the arguments are already on the stack and
  // we only add a handful of words to the stack

  // rbx: Method*
  // rcx: size of parameters
  // rbcp: sender sp
  __ pop(rax);                                       // get return address

  // for natives the size of locals is zero

  // compute beginning of parameters
  __ lea(rlocals, Address(rsp, rcx, Interpreter::stackElementScale(), -wordSize));

  // add 2 zero-initialized slots for native calls
  // initialize result_handler slot
  __ push(NULL_WORD);
  // slot for oop temp
  // (static native method holder mirror/jni oop result)
  __ push(NULL_WORD);

  // initialize fixed part of activation frame
  generate_fixed_frame(true);

  // make sure method is native & not abstract
#ifdef ASSERT
  __ load_unsigned_short(rax, access_flags);
  {
    Label L;
    __ testl(rax, JVM_ACC_NATIVE);
    __ jcc(Assembler::notZero, L);
    __ stop("tried to execute non-native method as native");
    __ bind(L);
  }
  {
    Label L;
    __ testl(rax, JVM_ACC_ABSTRACT);
    __ jcc(Assembler::zero, L);
    __ stop("tried to execute abstract method in interpreter");
    __ bind(L);
  }
#endif

  // Since at this point in the method invocation the exception handler
  // would try to exit the monitor of synchronized methods which hasn't
  // been entered yet, we set the thread local variable
  // _do_not_unlock_if_synchronized to true. The remove_activation will
  // check this flag.

  const Address do_not_unlock_if_synchronized(r15_thread,
        in_bytes(JavaThread::do_not_unlock_if_synchronized_offset()));
  __ movbool(do_not_unlock_if_synchronized, true);

  // increment invocation count & check for overflow
  Label invocation_counter_overflow;
  if (inc_counter) {
    generate_counter_incr(&invocation_counter_overflow);
  }

  Label continue_after_compile;
  __ bind(continue_after_compile);

  bang_stack_shadow_pages(true);

  // reset the _do_not_unlock_if_synchronized flag
  __ movbool(do_not_unlock_if_synchronized, false);

  // check for synchronized methods
  // Must happen AFTER invocation_counter check and stack overflow check,
  // so method is not locked if overflows.
  if (synchronized) {
    lock_method();
  } else {
    // no synchronization necessary
#ifdef ASSERT
    {
      Label L;
      __ load_unsigned_short(rax, access_flags);
      __ testl(rax, JVM_ACC_SYNCHRONIZED);
      __ jcc(Assembler::zero, L);
      __ stop("method needs synchronization");
      __ bind(L);
    }
#endif
  }

  // start execution
#ifdef ASSERT
  {
    Label L;
    const Address monitor_block_top(rbp,
                 frame::interpreter_frame_monitor_block_top_offset * wordSize);
    __ movptr(rax, monitor_block_top);
    __ lea(rax, Address(rbp, rax, Address::times_ptr));
    __ cmpptr(rax, rsp);
    __ jcc(Assembler::equal, L);
    __ stop("broken stack frame setup in interpreter 5");
    __ bind(L);
  }
#endif

  // jvmti support
  __ notify_method_entry();

  // work registers
  const Register method = rbx;
  const Register thread = r15_thread;
  const Register t      = r11;

  // allocate space for parameters
  __ get_method(method);
  __ movptr(t, Address(method, Method::const_offset()));
  __ load_unsigned_short(t, Address(t, ConstMethod::size_of_parameters_offset()));

  __ shll(t, Interpreter::logStackElementSize);

  __ subptr(rsp, t);
  __ subptr(rsp, frame::arg_reg_save_area_bytes); // windows
  __ andptr(rsp, -16); // must be 16 byte boundary (see amd64 ABI)

  // get signature handler
  {
    Label L;
    __ movptr(t, Address(method, Method::signature_handler_offset()));
    __ testptr(t, t);
    __ jcc(Assembler::notZero, L);
    __ call_VM(noreg,
               CAST_FROM_FN_PTR(address,
                                InterpreterRuntime::prepare_native_call),
               method);
    __ get_method(method);
    __ movptr(t, Address(method, Method::signature_handler_offset()));
    __ bind(L);
  }

  // call signature handler
  assert(InterpreterRuntime::SignatureHandlerGenerator::from() == rlocals,
         "adjust this code");
  assert(InterpreterRuntime::SignatureHandlerGenerator::to() == rsp,
         "adjust this code");
  assert(InterpreterRuntime::SignatureHandlerGenerator::temp() == rscratch1,
         "adjust this code");

  // The generated handlers do not touch RBX (the method).
  // However, large signatures cannot be cached and are generated
  // each time here.  The slow-path generator can do a GC on return,
  // so we must reload it after the call.
  __ call(t);
  __ get_method(method);        // slow path can do a GC, reload RBX


  // result handler is in rax
  // set result handler
  __ movptr(Address(rbp,
                    (frame::interpreter_frame_result_handler_offset) * wordSize),
            rax);

  // pass mirror handle if static call
  {
    Label L;
    __ load_unsigned_short(t, Address(method, Method::access_flags_offset()));
    __ testl(t, JVM_ACC_STATIC);
    __ jcc(Assembler::zero, L);
    // get mirror
    __ load_mirror(t, method, rax);
    // copy mirror into activation frame
    __ movptr(Address(rbp, frame::interpreter_frame_oop_temp_offset * wordSize),
            t);
    // pass handle to mirror
    __ lea(c_rarg1,
           Address(rbp, frame::interpreter_frame_oop_temp_offset * wordSize));
    __ bind(L);
  }

  // get native function entry point
  {
    Label L;
    __ movptr(rax, Address(method, Method::native_function_offset()));
    ExternalAddress unsatisfied(SharedRuntime::native_method_throw_unsatisfied_link_error_entry());
    __ cmpptr(rax, unsatisfied.addr(), rscratch1);
    __ jcc(Assembler::notEqual, L);
    __ call_VM(noreg,
               CAST_FROM_FN_PTR(address,
                                InterpreterRuntime::prepare_native_call),
               method);
    __ get_method(method);
    __ movptr(rax, Address(method, Method::native_function_offset()));
    __ bind(L);
  }

  // pass JNIEnv
   __ lea(c_rarg0, Address(r15_thread, JavaThread::jni_environment_offset()));

   // It is enough that the pc() points into the right code
   // segment. It does not have to be the correct return pc.
   // For convenience we use the pc we want to resume to in
   // case of preemption on Object.wait.
   Label native_return;
   __ set_last_Java_frame(rsp, rbp, native_return, rscratch1);

  // change thread state
#ifdef ASSERT
  {
    Label L;
    __ movl(t, Address(thread, JavaThread::thread_state_offset()));
    __ cmpl(t, _thread_in_Java);
    __ jcc(Assembler::equal, L);
    __ stop("Wrong thread state in native stub");
    __ bind(L);
  }
#endif

  // Change state to native

  __ movl(Address(thread, JavaThread::thread_state_offset()),
          _thread_in_native);

  __ push_cont_fastpath();

  // Call the native method.
  __ call(rax);
  // 32: result potentially in rdx:rax or ST0
  // 64: result potentially in rax or xmm0

  __ pop_cont_fastpath();

  // Verify or restore cpu control state after JNI call
  __ restore_cpu_control_state_after_jni(rscratch1);

  // NOTE: The order of these pushes is known to frame::interpreter_frame_result
  // in order to extract the result of a method call. If the order of these
  // pushes change or anything else is added to the stack then the code in
  // interpreter_frame_result must also change.

  __ push(dtos);
  __ push(ltos);

  // change thread state
  __ movl(Address(thread, JavaThread::thread_state_offset()),
          _thread_in_native_trans);

  // Force this write out before the read below
  if (!UseSystemMemoryBarrier) {
    __ membar(Assembler::Membar_mask_bits(
                Assembler::LoadLoad | Assembler::LoadStore |
                Assembler::StoreLoad | Assembler::StoreStore));
  }

  // check for safepoint operation in progress and/or pending suspend requests
  {
    Label Continue;
    Label slow_path;

    __ safepoint_poll(slow_path, thread, true /* at_return */, false /* in_nmethod */);

    __ cmpl(Address(thread, JavaThread::suspend_flags_offset()), 0);
    __ jcc(Assembler::equal, Continue);
    __ bind(slow_path);

    // Don't use call_VM as it will see a possible pending exception
    // and forward it and never return here preventing us from
    // clearing _last_native_pc down below.  Also can't use
    // call_VM_leaf either as it will check to see if r13 & r14 are
    // preserved and correspond to the bcp/locals pointers. So we do a
    // runtime call by hand.
    //
    __ mov(c_rarg0, r15_thread);
    __ mov(r12, rsp); // remember sp (can only use r12 if not using call_VM)
    __ subptr(rsp, frame::arg_reg_save_area_bytes); // windows
    __ andptr(rsp, -16); // align stack as required by ABI
    __ call(RuntimeAddress(CAST_FROM_FN_PTR(address, JavaThread::check_special_condition_for_native_trans)));
    __ mov(rsp, r12); // restore sp
    __ reinit_heapbase();
    __ bind(Continue);
  }

  // change thread state
  __ movl(Address(thread, JavaThread::thread_state_offset()), _thread_in_Java);

  if (LockingMode != LM_LEGACY) {
    // Check preemption for Object.wait()
    Label not_preempted;
    __ movptr(rscratch1, Address(r15_thread, JavaThread::preempt_alternate_return_offset()));
    __ cmpptr(rscratch1, NULL_WORD);
    __ jccb(Assembler::equal, not_preempted);
    __ movptr(Address(r15_thread, JavaThread::preempt_alternate_return_offset()), NULL_WORD);
    __ jmp(rscratch1);
    __ bind(native_return);
    __ restore_after_resume(true /* is_native */);
    __ bind(not_preempted);
  } else {
    // any pc will do so just use this one for LM_LEGACY to keep code together.
    __ bind(native_return);
  }

  // reset_last_Java_frame
  __ reset_last_Java_frame(thread, true);

  if (CheckJNICalls) {
    // clear_pending_jni_exception_check
    __ movptr(Address(thread, JavaThread::pending_jni_exception_check_fn_offset()), NULL_WORD);
  }

  // reset handle block
  __ movptr(t, Address(thread, JavaThread::active_handles_offset()));
  __ movl(Address(t, JNIHandleBlock::top_offset()), NULL_WORD);

  // If result is an oop unbox and store it in frame where gc will see it
  // and result handler will pick it up

  {
    Label no_oop;
    __ lea(t, ExternalAddress(AbstractInterpreter::result_handler(T_OBJECT)));
    __ cmpptr(t, Address(rbp, frame::interpreter_frame_result_handler_offset*wordSize));
    __ jcc(Assembler::notEqual, no_oop);
    // retrieve result
    __ pop(ltos);
    // Unbox oop result, e.g. JNIHandles::resolve value.
    __ resolve_jobject(rax /* value */,
                       thread /* thread */,
                       t /* tmp */);
    __ movptr(Address(rbp, frame::interpreter_frame_oop_temp_offset*wordSize), rax);
    // keep stack depth as expected by pushing oop which will eventually be discarded
    __ push(ltos);
    __ bind(no_oop);
  }


  {
    Label no_reguard;
    __ cmpl(Address(thread, JavaThread::stack_guard_state_offset()),
            StackOverflow::stack_guard_yellow_reserved_disabled);
    __ jcc(Assembler::notEqual, no_reguard);

    __ pusha(); // XXX only save smashed registers
    __ mov(r12, rsp); // remember sp (can only use r12 if not using call_VM)
    __ subptr(rsp, frame::arg_reg_save_area_bytes); // windows
    __ andptr(rsp, -16); // align stack as required by ABI
    __ call(RuntimeAddress(CAST_FROM_FN_PTR(address, SharedRuntime::reguard_yellow_pages)));
    __ mov(rsp, r12); // restore sp
    __ popa(); // XXX only restore smashed registers
    __ reinit_heapbase();

    __ bind(no_reguard);
  }


  // The method register is junk from after the thread_in_native transition
  // until here.  Also can't call_VM until the bcp has been
  // restored.  Need bcp for throwing exception below so get it now.
  __ get_method(method);

  // restore to have legal interpreter frame, i.e., bci == 0 <=> code_base()
  __ movptr(rbcp, Address(method, Method::const_offset()));   // get ConstMethod*
  __ lea(rbcp, Address(rbcp, ConstMethod::codes_offset()));    // get codebase

  // handle exceptions (exception handling will handle unlocking!)
  {
    Label L;
    __ cmpptr(Address(thread, Thread::pending_exception_offset()), NULL_WORD);
    __ jcc(Assembler::zero, L);
    // Note: At some point we may want to unify this with the code
    // used in call_VM_base(); i.e., we should use the
    // StubRoutines::forward_exception code. For now this doesn't work
    // here because the rsp is not correctly set at this point.
    __ MacroAssembler::call_VM(noreg,
                               CAST_FROM_FN_PTR(address,
                               InterpreterRuntime::throw_pending_exception));
    __ should_not_reach_here();
    __ bind(L);
  }

  // do unlocking if necessary
  {
    Label L;
    __ load_unsigned_short(t, Address(method, Method::access_flags_offset()));
    __ testl(t, JVM_ACC_SYNCHRONIZED);
    __ jcc(Assembler::zero, L);
    // the code below should be shared with interpreter macro
    // assembler implementation
    {
      Label unlock;
      // BasicObjectLock will be first in list, since this is a
      // synchronized method. However, need to check that the object
      // has not been unlocked by an explicit monitorexit bytecode.
      const Address monitor(rbp,
                            (intptr_t)(frame::interpreter_frame_initial_sp_offset *
                                       wordSize - (int)sizeof(BasicObjectLock)));

      const Register regmon = c_rarg1;

      // monitor expect in c_rarg1 for slow unlock path
      __ lea(regmon, monitor); // address of first monitor

      __ movptr(t, Address(regmon, BasicObjectLock::obj_offset()));
      __ testptr(t, t);
      __ jcc(Assembler::notZero, unlock);

      // Entry already unlocked, need to throw exception
      __ MacroAssembler::call_VM(noreg,
                                 CAST_FROM_FN_PTR(address,
                   InterpreterRuntime::throw_illegal_monitor_state_exception));
      __ should_not_reach_here();

      __ bind(unlock);
      __ unlock_object(regmon);
    }
    __ bind(L);
  }

  // jvmti support
  // Note: This must happen _after_ handling/throwing any exceptions since
  //       the exception handler code notifies the runtime of method exits
  //       too. If this happens before, method entry/exit notifications are
  //       not properly paired (was bug - gri 11/22/99).
  __ notify_method_exit(vtos, InterpreterMacroAssembler::NotifyJVMTI);

  // restore potential result in edx:eax, call result handler to
  // restore potential result in ST0 & handle result

  __ pop(ltos);
  __ pop(dtos);

  __ movptr(t, Address(rbp,
                       (frame::interpreter_frame_result_handler_offset) * wordSize));
  __ call(t);

  // remove activation
  __ movptr(t, Address(rbp,
                       frame::interpreter_frame_sender_sp_offset *
                       wordSize)); // get sender sp
  __ leave();                                // remove frame anchor
  __ pop(rdi);                               // get return address
  __ mov(rsp, t);                            // set sp to sender sp
  __ jmp(rdi);

  if (inc_counter) {
    // Handle overflow of counter and compile method
    __ bind(invocation_counter_overflow);
    generate_counter_overflow(continue_after_compile);
  }

  return entry_point;
}

// Abstract method entry
// Attempt to execute abstract method. Throw exception
address TemplateInterpreterGenerator::generate_abstract_entry(void) {

  address entry_point = __ pc();

  // abstract method entry

  //  pop return address, reset last_sp to null
  __ empty_expression_stack();
  __ restore_bcp();      // rsi must be correct for exception handler   (was destroyed)
  __ restore_locals();   // make sure locals pointer is correct as well (was destroyed)

  // throw exception
  __ call_VM(noreg, CAST_FROM_FN_PTR(address, InterpreterRuntime::throw_AbstractMethodErrorWithMethod), rbx);
  // the call_VM checks for exception, so we should never return here.
  __ should_not_reach_here();

  return entry_point;
}

//
// Generic interpreted method entry to (asm) interpreter
//
address TemplateInterpreterGenerator::generate_normal_entry(bool synchronized) {
  // determine code generation flags
  bool inc_counter  = UseCompiler || CountCompiledCalls;

  // ebx: Method*
  // rbcp: sender sp (set in InterpreterMacroAssembler::prepare_to_jump_from_interpreted / generate_call_stub)
  address entry_point = __ pc();

  const Address constMethod(rbx, Method::const_offset());
  const Address access_flags(rbx, Method::access_flags_offset());
  const Address size_of_parameters(rdx,
                                   ConstMethod::size_of_parameters_offset());
  const Address size_of_locals(rdx, ConstMethod::size_of_locals_offset());


  // get parameter size (always needed)
  __ movptr(rdx, constMethod);
  __ load_unsigned_short(rcx, size_of_parameters);

  // rbx: Method*
  // rcx: size of parameters
  // rbcp: sender_sp (could differ from sp+wordSize if we were called via c2i )

  __ load_unsigned_short(rdx, size_of_locals); // get size of locals in words
  __ subl(rdx, rcx); // rdx = no. of additional locals

  // YYY
//   __ incrementl(rdx);
//   __ andl(rdx, -2);

  // see if we've got enough room on the stack for locals plus overhead.
  generate_stack_overflow_check();

  // get return address
  __ pop(rax);

  // compute beginning of parameters
  __ lea(rlocals, Address(rsp, rcx, Interpreter::stackElementScale(), -wordSize));

  // rdx - # of additional locals
  // allocate space for locals
  // explicitly initialize locals
  {
    Label exit, loop;
    __ testl(rdx, rdx);
    __ jcc(Assembler::lessEqual, exit); // do nothing if rdx <= 0
    __ bind(loop);
    __ push(NULL_WORD); // initialize local variables
    __ decrementl(rdx); // until everything initialized
    __ jcc(Assembler::greater, loop);
    __ bind(exit);
  }

  // initialize fixed part of activation frame
  generate_fixed_frame(false);

  // make sure method is not native & not abstract
#ifdef ASSERT
  __ load_unsigned_short(rax, access_flags);
  {
    Label L;
    __ testl(rax, JVM_ACC_NATIVE);
    __ jcc(Assembler::zero, L);
    __ stop("tried to execute native method as non-native");
    __ bind(L);
  }
  {
    Label L;
    __ testl(rax, JVM_ACC_ABSTRACT);
    __ jcc(Assembler::zero, L);
    __ stop("tried to execute abstract method in interpreter");
    __ bind(L);
  }
#endif

  // Since at this point in the method invocation the exception
  // handler would try to exit the monitor of synchronized methods
  // which hasn't been entered yet, we set the thread local variable
  // _do_not_unlock_if_synchronized to true. The remove_activation
  // will check this flag.

  const Address do_not_unlock_if_synchronized(r15_thread,
        in_bytes(JavaThread::do_not_unlock_if_synchronized_offset()));
  __ movbool(do_not_unlock_if_synchronized, true);

  __ profile_parameters_type(rax, rcx, rdx);
  // increment invocation count & check for overflow
  Label invocation_counter_overflow;
  if (inc_counter) {
    generate_counter_incr(&invocation_counter_overflow);
  }

  Label continue_after_compile;
  __ bind(continue_after_compile);

  // check for synchronized interpreted methods
  bang_stack_shadow_pages(false);

  // reset the _do_not_unlock_if_synchronized flag
  __ movbool(do_not_unlock_if_synchronized, false);

  // check for synchronized methods
  // Must happen AFTER invocation_counter check and stack overflow check,
  // so method is not locked if overflows.
  if (synchronized) {
    // Allocate monitor and lock method
    lock_method();
  } else {
    // no synchronization necessary
#ifdef ASSERT
    {
      Label L;
      __ load_unsigned_short(rax, access_flags);
      __ testl(rax, JVM_ACC_SYNCHRONIZED);
      __ jcc(Assembler::zero, L);
      __ stop("method needs synchronization");
      __ bind(L);
    }
#endif
  }

  // start execution
#ifdef ASSERT
  {
    Label L;
     const Address monitor_block_top (rbp,
                 frame::interpreter_frame_monitor_block_top_offset * wordSize);
    __ movptr(rax, monitor_block_top);
    __ lea(rax, Address(rbp, rax, Address::times_ptr));
    __ cmpptr(rax, rsp);
    __ jcc(Assembler::equal, L);
    __ stop("broken stack frame setup in interpreter 6");
    __ bind(L);
  }
#endif

  // jvmti support
  __ notify_method_entry();

  __ dispatch_next(vtos);

  // invocation counter overflow
  if (inc_counter) {
    // Handle overflow of counter and compile method
    __ bind(invocation_counter_overflow);
    generate_counter_overflow(continue_after_compile);
  }

  return entry_point;
}

//-----------------------------------------------------------------------------
// Exceptions

void TemplateInterpreterGenerator::generate_throw_exception() {
  // Entry point in previous activation (i.e., if the caller was
  // interpreted)
  Interpreter::_rethrow_exception_entry = __ pc();
  // Restore sp to interpreter_frame_last_sp even though we are going
  // to empty the expression stack for the exception processing.
  __ movptr(Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize), NULL_WORD);
  // rax: exception
  // rdx: return address/pc that threw exception
  __ restore_bcp();    // r13/rsi points to call/send
  __ restore_locals();
  __ reinit_heapbase();  // restore r12 as heapbase.
  // Entry point for exceptions thrown within interpreter code
  Interpreter::_throw_exception_entry = __ pc();
  // expression stack is undefined here
  // rax: exception
  // r13/rsi: exception bcp
  __ verify_oop(rax);
  __ mov(c_rarg1, rax);

  // expression stack must be empty before entering the VM in case of
  // an exception
  __ empty_expression_stack();
  // find exception handler address and preserve exception oop
  __ call_VM(rdx,
             CAST_FROM_FN_PTR(address,
                          InterpreterRuntime::exception_handler_for_exception),
             c_rarg1);
  // rax: exception handler entry point
  // rdx: preserved exception oop
  // r13/rsi: bcp for exception handler
  __ push_ptr(rdx); // push exception which is now the only value on the stack
  __ jmp(rax); // jump to exception handler (may be _remove_activation_entry!)

  // If the exception is not handled in the current frame the frame is
  // removed and the exception is rethrown (i.e. exception
  // continuation is _rethrow_exception).
  //
  // Note: At this point the bci is still the bxi for the instruction
  // which caused the exception and the expression stack is
  // empty. Thus, for any VM calls at this point, GC will find a legal
  // oop map (with empty expression stack).

  // In current activation
  // tos: exception
  // esi: exception bcp

  //
  // JVMTI PopFrame support
  //

  Interpreter::_remove_activation_preserving_args_entry = __ pc();
  __ empty_expression_stack();
  // Set the popframe_processing bit in pending_popframe_condition
  // indicating that we are currently handling popframe, so that
  // call_VMs that may happen later do not trigger new popframe
  // handling cycles.
  const Register thread = r15_thread;
  __ movl(rdx, Address(thread, JavaThread::popframe_condition_offset()));
  __ orl(rdx, JavaThread::popframe_processing_bit);
  __ movl(Address(thread, JavaThread::popframe_condition_offset()), rdx);

  {
    // Check to see whether we are returning to a deoptimized frame.
    // (The PopFrame call ensures that the caller of the popped frame is
    // either interpreted or compiled and deoptimizes it if compiled.)
    // In this case, we can't call dispatch_next() after the frame is
    // popped, but instead must save the incoming arguments and restore
    // them after deoptimization has occurred.
    //
    // Note that we don't compare the return PC against the
    // deoptimization blob's unpack entry because of the presence of
    // adapter frames in C2.
    Label caller_not_deoptimized;
    __ movptr(c_rarg1, Address(rbp, frame::return_addr_offset * wordSize));
    __ super_call_VM_leaf(CAST_FROM_FN_PTR(address,
                               InterpreterRuntime::interpreter_contains), c_rarg1);
    __ testl(rax, rax);
    __ jcc(Assembler::notZero, caller_not_deoptimized);

    // Compute size of arguments for saving when returning to
    // deoptimized caller
    __ get_method(rax);
    __ movptr(rax, Address(rax, Method::const_offset()));
    __ load_unsigned_short(rax, Address(rax, in_bytes(ConstMethod::
                                                size_of_parameters_offset())));
    __ shll(rax, Interpreter::logStackElementSize);
    __ restore_locals();
    __ subptr(rlocals, rax);
    __ addptr(rlocals, wordSize);
    // Save these arguments
    __ super_call_VM_leaf(CAST_FROM_FN_PTR(address,
                                           Deoptimization::
                                           popframe_preserve_args),
                          thread, rax, rlocals);

    __ remove_activation(vtos, rdx,
                         /* throw_monitor_exception */ false,
                         /* install_monitor_exception */ false,
                         /* notify_jvmdi */ false);

    // Inform deoptimization that it is responsible for restoring
    // these arguments
    __ movl(Address(thread, JavaThread::popframe_condition_offset()),
            JavaThread::popframe_force_deopt_reexecution_bit);

    // Continue in deoptimization handler
    __ jmp(rdx);

    __ bind(caller_not_deoptimized);
  }

  __ remove_activation(vtos, rdx, /* rdx result (retaddr) is not used */
                       /* throw_monitor_exception */ false,
                       /* install_monitor_exception */ false,
                       /* notify_jvmdi */ false);

  // Finish with popframe handling
  // A previous I2C followed by a deoptimization might have moved the
  // outgoing arguments further up the stack. PopFrame expects the
  // mutations to those outgoing arguments to be preserved and other
  // constraints basically require this frame to look exactly as
  // though it had previously invoked an interpreted activation with
  // no space between the top of the expression stack (current
  // last_sp) and the top of stack. Rather than force deopt to
  // maintain this kind of invariant all the time we call a small
  // fixup routine to move the mutated arguments onto the top of our
  // expression stack if necessary.
  __ mov(c_rarg1, rsp);
  __ movptr(c_rarg2, Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize));
  __ lea(c_rarg2, Address(rbp, c_rarg2, Address::times_ptr));
  // PC must point into interpreter here
  __ set_last_Java_frame(noreg, rbp, __ pc(), rscratch1);
  __ super_call_VM_leaf(CAST_FROM_FN_PTR(address, InterpreterRuntime::popframe_move_outgoing_args), r15_thread, c_rarg1, c_rarg2);
  __ reset_last_Java_frame(thread, true);

  // Restore the last_sp and null it out
  __ movptr(rcx, Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize));
  __ lea(rsp, Address(rbp, rcx, Address::times_ptr));
  __ movptr(Address(rbp, frame::interpreter_frame_last_sp_offset * wordSize), NULL_WORD);

  __ restore_bcp();
  __ restore_locals();
  // The method data pointer was incremented already during
  // call profiling. We have to restore the mdp for the current bcp.
  if (ProfileInterpreter) {
    __ set_method_data_pointer_for_bcp();
  }

  // Clear the popframe condition flag
  __ movl(Address(thread, JavaThread::popframe_condition_offset()),
          JavaThread::popframe_inactive);

#if INCLUDE_JVMTI
  {
    Label L_done;
    const Register local0 = rlocals;

    __ cmpb(Address(rbcp, 0), Bytecodes::_invokestatic);
    __ jcc(Assembler::notEqual, L_done);

    // The member name argument must be restored if _invokestatic is re-executed after a PopFrame call.
    // Detect such a case in the InterpreterRuntime function and return the member name argument, or null.

    __ get_method(rdx);
    __ movptr(rax, Address(local0, 0));
    __ call_VM(rax, CAST_FROM_FN_PTR(address, InterpreterRuntime::member_name_arg_or_null), rax, rdx, rbcp);

    __ testptr(rax, rax);
    __ jcc(Assembler::zero, L_done);

    __ movptr(Address(rbx, 0), rax);
    __ bind(L_done);
  }
#endif // INCLUDE_JVMTI

  __ dispatch_next(vtos);
  // end of PopFrame support

  Interpreter::_remove_activation_entry = __ pc();

  // preserve exception over this code sequence
  __ pop_ptr(rax);
  __ movptr(Address(thread, JavaThread::vm_result_offset()), rax);
  // remove the activation (without doing throws on illegalMonitorExceptions)
  __ remove_activation(vtos, rdx, false, true, false);
  // restore exception
  __ get_vm_result(rax, thread);

  // In between activations - previous activation type unknown yet
  // compute continuation point - the continuation point expects the
  // following registers set up:
  //
  // rax: exception
  // rdx: return address/pc that threw exception
  // rsp: expression stack of caller
  // rbp: ebp of caller
  __ push(rax);                                  // save exception
  __ push(rdx);                                  // save return address
  __ super_call_VM_leaf(CAST_FROM_FN_PTR(address,
                          SharedRuntime::exception_handler_for_return_address),
                        thread, rdx);
  __ mov(rbx, rax);                              // save exception handler
  __ pop(rdx);                                   // restore return address
  __ pop(rax);                                   // restore exception
  // Note that an "issuing PC" is actually the next PC after the call
  __ jmp(rbx);                                   // jump to exception
                                                 // handler of caller
}


//
// JVMTI ForceEarlyReturn support
//
address TemplateInterpreterGenerator::generate_earlyret_entry_for(TosState state) {
  address entry = __ pc();

  __ restore_bcp();
  __ restore_locals();
  __ empty_expression_stack();
  __ load_earlyret_value(state);  // 32 bits returns value in rdx, so don't reuse

  __ movptr(rcx, Address(r15_thread, JavaThread::jvmti_thread_state_offset()));
  Address cond_addr(rcx, JvmtiThreadState::earlyret_state_offset());

  // Clear the earlyret state
  __ movl(cond_addr, JvmtiThreadState::earlyret_inactive);

  __ remove_activation(state, rsi,
                       false, /* throw_monitor_exception */
                       false, /* install_monitor_exception */
                       true); /* notify_jvmdi */
  __ jmp(rsi);

  return entry;
} // end of ForceEarlyReturn support


//-----------------------------------------------------------------------------
// Helper for vtos entry point generation

void TemplateInterpreterGenerator::set_vtos_entry_points(Template* t,
                                                         address& bep,
                                                         address& cep,
                                                         address& sep,
                                                         address& aep,
                                                         address& iep,
                                                         address& lep,
                                                         address& fep,
                                                         address& dep,
                                                         address& vep) {
  assert(t->is_valid() && t->tos_in() == vtos, "illegal template");
  Label L;
  fep = __ pc();     // ftos entry point
      __ push_f(xmm0);
      __ jmpb(L);
  dep = __ pc();     // dtos entry point
      __ push_d(xmm0);
      __ jmpb(L);
  lep = __ pc();     // ltos entry point
      __ push_l();
      __ jmpb(L);
  aep = bep = cep = sep = iep = __ pc();      // [abcsi]tos entry point
      __ push_i_or_ptr();
  vep = __ pc();    // vtos entry point
  __ bind(L);
  generate_and_dispatch(t);
}

//-----------------------------------------------------------------------------

// Non-product code
#ifndef PRODUCT

address TemplateInterpreterGenerator::generate_trace_code(TosState state) {
  address entry = __ pc();

  __ push(state);
  __ push(c_rarg0);
  __ push(c_rarg1);
  __ push(c_rarg2);
  __ push(c_rarg3);
  __ mov(c_rarg2, rax);  // Pass itos
#ifdef _WIN64
  __ movflt(xmm3, xmm0); // Pass ftos
#endif
  __ call_VM(noreg,
             CAST_FROM_FN_PTR(address, InterpreterRuntime::trace_bytecode),
             c_rarg1, c_rarg2, c_rarg3);
  __ pop(c_rarg3);
  __ pop(c_rarg2);
  __ pop(c_rarg1);
  __ pop(c_rarg0);
  __ pop(state);
  __ ret(0);                                   // return from result handler

  return entry;
}

void TemplateInterpreterGenerator::count_bytecode() {
  __ incrementq(ExternalAddress((address) &BytecodeCounter::_counter_value), rscratch1);
}

void TemplateInterpreterGenerator::histogram_bytecode(Template* t) {
  __ incrementl(ExternalAddress((address) &BytecodeHistogram::_counters[t->bytecode()]), rscratch1);
}

void TemplateInterpreterGenerator::histogram_bytecode_pair(Template* t) {
  __ mov32(rbx, ExternalAddress((address) &BytecodePairHistogram::_index));
  __ shrl(rbx, BytecodePairHistogram::log2_number_of_codes);
  __ orl(rbx,
         ((int) t->bytecode()) <<
         BytecodePairHistogram::log2_number_of_codes);
  __ mov32(ExternalAddress((address) &BytecodePairHistogram::_index), rbx, rscratch1);
  __ lea(rscratch1, ExternalAddress((address) BytecodePairHistogram::_counters));
  __ incrementl(Address(rscratch1, rbx, Address::times_4));
}


void TemplateInterpreterGenerator::trace_bytecode(Template* t) {
  // Call a little run-time stub to avoid blow-up for each bytecode.
  // The run-time runtime saves the right registers, depending on
  // the tosca in-state for the given template.

  assert(Interpreter::trace_code(t->tos_in()) != nullptr,
         "entry must have been generated");
  __ mov(r12, rsp); // remember sp (can only use r12 if not using call_VM)
  __ andptr(rsp, -16); // align stack as required by ABI
  __ call(RuntimeAddress(Interpreter::trace_code(t->tos_in())));
  __ mov(rsp, r12); // restore sp
  __ reinit_heapbase();
}


void TemplateInterpreterGenerator::stop_interpreter_at() {
  Label L;
  __ mov64(rscratch1, StopInterpreterAt);
  __ cmp64(rscratch1, ExternalAddress((address) &BytecodeCounter::_counter_value), rscratch2);
  __ jcc(Assembler::notEqual, L);
  __ int3();
  __ bind(L);
}
#endif // !PRODUCT
