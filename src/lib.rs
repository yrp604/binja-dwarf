use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use log::*;

use binja::architecture;
use binja::architecture::CoreArchitecture;
use binja::architecture::CustomArchitectureHandle;
use binja::architecture::InstructionInfo;
use binja::architecture::{
    FlagCondition, FlagRole, ImplicitRegisterExtend, Register as Reg, RegisterInfo,
};

use binja::llil;
use binja::llil::{Label, Liftable, LiftableWithSize, LiftedExpr, LiftedNonSSA, Mutable, NonSSA};

use dwarf_dis::{decode, Op};

const MAX_REG_NO: u32 = 33;
const REG_SP: u32 = MAX_REG_NO;
// dwarf doesn't have a link register, however if we define one binja will
// render our stacks better, because it will use it for return addresses
// instead of using our stack
const REG_LR: u32 = MAX_REG_NO - 1;

#[derive(Copy, Clone)]
struct Register {
    id: u32,
}

impl Register {
    fn new(id: u32) -> Self {
        Self { id }
    }
}

impl Into<llil::Register<Register>> for Register {
    fn into(self) -> llil::Register<Register> {
        llil::Register::ArchReg(self)
    }
}

impl architecture::RegisterInfo for Register {
    type RegType = Self;

    fn parent(&self) -> Option<Self> {
        None
    }
    fn offset(&self) -> usize {
        0
    }

    fn size(&self) -> usize {
        8
    }

    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        ImplicitRegisterExtend::NoExtend
    }
}

impl architecture::Register for Register {
    type InfoType = Self;

    fn name(&self) -> Cow<str> {
        match self.id {
            0..=31 => format!("reg{}", self.id).into(),
            REG_LR => "fake_lr".into(),
            REG_SP => "sp".into(),
            _ => panic!("bad register number"),
        }
    }

    fn info(&self) -> Self {
        *self
    }

    fn id(&self) -> u32 {
        self.id
    }
}

impl<'a> Liftable<'a, DwarfArch> for Register {
    type Result = llil::ValueExpr;

    fn lift(
        il: &'a llil::Lifter<DwarfArch>,
        reg: Self,
    ) -> llil::Expression<'a, DwarfArch, Mutable, NonSSA<LiftedNonSSA>, Self::Result> {
        il.reg(reg.size(), reg)
    }
}

impl<'a> LiftableWithSize<'a, DwarfArch> for Register {
    fn lift_with_size(
        il: &'a llil::Lifter<DwarfArch>,
        reg: Self,
        size: usize,
    ) -> llil::Expression<'a, DwarfArch, Mutable, NonSSA<LiftedNonSSA>, llil::ValueExpr> {
        #[cfg(debug_assertions)]
        {
            if reg.size() < size {
                warn!(
                    "il @ {:x} attempted to lift {} byte register as {} byte expr",
                    il.current_address(),
                    reg.size(),
                    size
                );
            }
        }

        il.reg(reg.size(), reg)
    }
}

impl fmt::Debug for Register {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name().as_ref())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
struct Flag;

impl architecture::Flag for Flag {
    type FlagClass = Self;

    fn name(&self) -> Cow<str> {
        unreachable!()
    }

    fn role(&self, _class: Option<Self::FlagClass>) -> FlagRole {
        unreachable!()
    }

    fn id(&self) -> u32 {
        unreachable!()
    }
}

impl architecture::FlagWrite for Flag {
    type FlagType = Self;
    type FlagClass = Self;

    fn name(&self) -> Cow<str> {
        unreachable!()
    }

    fn id(&self) -> u32 {
        unreachable!()
    }

    fn class(&self) -> Option<Self> {
        unreachable!()
    }

    fn flags_written(&self) -> Vec<Self::FlagType> {
        unreachable!()
    }
}

impl architecture::FlagClass for Flag {
    fn name(&self) -> Cow<str> {
        unreachable!()
    }

    fn id(&self) -> u32 {
        unreachable!()
    }
}

impl architecture::FlagGroup for Flag {
    type FlagType = Self;
    type FlagClass = Self;

    fn name(&self) -> Cow<str> {
        unreachable!()
    }

    fn id(&self) -> u32 {
        unreachable!()
    }

    fn flags_required(&self) -> Vec<Self::FlagType> {
        unreachable!()
    }

    fn flag_conditions(&self) -> HashMap<Self, FlagCondition> {
        unreachable!()
    }
}

struct DwarfArch {
    handle: CoreArchitecture,
    custom_handle: CustomArchitectureHandle<DwarfArch>,
}

impl architecture::Architecture for DwarfArch {
    type Handle = CustomArchitectureHandle<Self>;

    type RegisterInfo = Register;
    type Register = Register;

    type Flag = Flag;
    type FlagWrite = Flag;
    type FlagClass = Flag;
    type FlagGroup = Flag;

    type InstructionTextContainer = Vec<architecture::InstructionTextToken>;

    fn endianness(&self) -> binja::Endianness {
        binja::Endianness::LittleEndian
    }

    fn address_size(&self) -> usize {
        8
    }

    fn default_integer_size(&self) -> usize {
        8
    }

    fn instruction_alignment(&self) -> usize {
        1
    }

    fn max_instr_len(&self) -> usize {
        10
    }

    fn opcode_display_len(&self) -> usize {
        self.max_instr_len()
    }

    fn associated_arch_by_addr(&self, _addr: &mut u64) -> CoreArchitecture {
        self.handle
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        use architecture::BranchInfo;

        debug!("decode {:#x}", addr);
        let (sz, op) = decode(data).ok()?;
        let pc = addr.wrapping_add(sz as u64);

        let mut res = InstructionInfo::new(sz, false);

        match op {
            Op::Bra(off) => {
                res.add_branch(BranchInfo::True(pc.wrapping_add(off as i64 as u64)), None);
                res.add_branch(BranchInfo::False(pc as u64), None);
            }
            Op::Skip(off) => {
                let target = pc.wrapping_add(off as i64 as u64);

                res.add_branch(BranchInfo::Unconditional(target), None);
            }
            _ => (),
        }

        Some(res)
    }

    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Self::InstructionTextContainer)> {
        use architecture::InstructionTextToken;
        use architecture::InstructionTextTokenContents::*;

        debug!("decode {:#x}", addr);
        let (sz, op) = decode(data).ok()?;
        let pc = addr.wrapping_add(sz as u64);

        let mnem = op.mnem();
        let pad_len = 10usize.saturating_sub(mnem.len());

        let mut res = Vec::new();

        res.push(InstructionTextToken::new(Instruction, mnem));

        // Get all the ops that have an argument, add a space
        match op {
            Op::Const1u(_)
            | Op::Const1s(_)
            | Op::Const2u(_)
            | Op::Const2s(_)
            | Op::Const4u(_)
            | Op::Const4s(_)
            | Op::Const8u(_)
            | Op::Const8s(_)
            | Op::Constu(_)
            | Op::Consts(_)
            | Op::Pick(_)
            | Op::PlusConst(_)
            | Op::Bra(_)
            | Op::Skip(_)
            | Op::Lit(_)
            | Op::Reg(_)
            | Op::BReg(_, _)
            | Op::RegX(_)
            | Op::BRegX(_, _)
            | Op::DerefSize(_) => res.push(InstructionTextToken::new(Text, " ")),
            _ => (),
        }

        match op {
            Op::Const1u(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("{:#x}", v),
                ));
            }
            Op::Const1s(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("-{:#x}", v),
                ));
            }
            Op::Const2u(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("{:#x}", v),
                ));
            }
            Op::Const2s(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("-{:#x}", v),
                ));
            }
            Op::Const4u(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("{:#x}", v),
                ));
            }
            Op::Const4s(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("-{:#x}", v),
                ));
            }
            Op::Const8u(v) | Op::Constu(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("{:#x}", v),
                ));
            }
            Op::Const8s(v) | Op::Consts(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("-{:#x}", v),
                ));
            }
            Op::Pick(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("{:#x}", v),
                ));
            }
            Op::PlusConst(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("{:#x}", v),
                ));
            }
            Op::Lit(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("{:#x}", v),
                ));
            }
            Op::Bra(off) | Op::Skip(off) => {
                let target = pc.wrapping_add(off as i64 as u64);

                res.push(InstructionTextToken::new(
                    CodeRelativeAddress(target),
                    format!("{:#x}", target),
                ));
            }
            Op::Reg(r) => {
                let reg = self::Register::new(r.into());

                res.push(InstructionTextToken::new(Register, reg.name().as_bytes()));
            }
            Op::BReg(_, _) => todo!(),
            Op::DerefSize(v) => {
                res.push(InstructionTextToken::new(
                    Integer(v as u64),
                    format!("{:#x}", v),
                ));
            }
            _ => res.push(InstructionTextToken::new(
                Text,
                format!("{:1$}", " ", pad_len),
            )),
        }

        Some((sz, res))
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &mut llil::Lifter<Self>,
    ) -> Option<(usize, bool)> {
        debug!("lifting {:#x}", addr);

        let (sz, op) = decode(data).ok()?;

        let pc = addr.wrapping_add(sz as u64);

        let mut cont = true;

        match op {
            Op::Addr(a) => il.push(8, il.load(8, a)).append(),
            Op::Deref => il.push(8, il.load(8, il.pop(8))).append(),
            Op::Const1u(v) => il.push(8, v as u64).append(),
            Op::Const1s(v) => il.push(8, v as u64).append(),
            Op::Const2u(v) => il.push(8, v as u64).append(),
            Op::Const2s(v) => il.push(8, v as u64).append(),
            Op::Const4u(v) => il.push(8, v as u64).append(),
            Op::Const4s(v) => il.push(8, v as u64).append(),
            Op::Const8u(v) | Op::Constu(v) => il.push(8, v as u64).append(),
            Op::Const8s(v) | Op::Consts(v) => il.push(8, v as u64).append(),
            Op::Dup => {
                il.set_reg(8, llil::Register::Temp(0), il.pop(8)).append();

                il.push(8, il.reg(8, llil::Register::Temp(0))).append();
                il.push(8, il.reg(8, llil::Register::Temp(0))).append();
            }
            Op::Drop => il.pop(8).append(),
            Op::Over => {
                il.set_reg(
                    8,
                    llil::Register::Temp(0),
                    il.load(8, il.add(8, il.reg(8, Register::new(MAX_REG_NO)), 8u64)),
                )
                .append();

                il.push(8, il.reg(8, llil::Register::Temp(0))).append();
            }
            Op::Pick(off) => {
                il.set_reg(
                    8,
                    llil::Register::Temp(0),
                    il.load(
                        8,
                        il.add(
                            8,
                            il.reg(8, Register::new(MAX_REG_NO)),
                            il.mul(8, 8u64, off),
                        ),
                    ),
                )
                .append();

                il.push(8, il.reg(8, llil::Register::Temp(0))).append();
            }
            Op::Swap => {
                il.set_reg(8, llil::Register::Temp(0), il.pop(8)).append();
                il.set_reg(8, llil::Register::Temp(1), il.pop(8)).append();

                il.push(8, il.reg(8, llil::Register::Temp(0))).append();
                il.push(8, il.reg(8, llil::Register::Temp(1))).append();
            }
            Op::Rot => {
                il.set_reg(8, llil::Register::Temp(0), il.pop(8)).append();
                il.set_reg(8, llil::Register::Temp(1), il.pop(8)).append();
                il.set_reg(8, llil::Register::Temp(2), il.pop(8)).append();

                il.push(8, il.reg(8, llil::Register::Temp(1))).append();
                il.push(8, il.reg(8, llil::Register::Temp(2))).append();
                il.push(8, il.reg(8, llil::Register::Temp(0))).append();
            }
            Op::Abs => {
                // bit hack for abs:
                // x = pop()
                // y = x >>> 63
                // push((x ^ y) - y)

                il.set_reg(8, llil::Register::Temp(0), il.pop(8)).append();
                il.set_reg(
                    8,
                    llil::Register::Temp(1),
                    il.asr(8, il.reg(8, llil::Register::Temp(0)), 63),
                )
                .append();

                il.push(
                    8,
                    il.sub(
                        8,
                        il.xor(
                            8,
                            il.reg(8, llil::Register::Temp(0)),
                            il.reg(8, llil::Register::Temp(1)),
                        ),
                        il.reg(8, llil::Register::Temp(1)),
                    ),
                )
                .append();
            }
            Op::And => il.push(8, il.and(8, il.pop(8), il.pop(8))).append(),
            Op::Div => il.push(8, il.divu(8, il.pop(8), il.pop(8))).append(),
            Op::Minus => il.push(8, il.sub(8, il.pop(8), il.pop(8))).append(),
            Op::Mod => il.push(8, il.modu(8, il.pop(8), il.pop(8))).append(),
            Op::Mul => il.push(8, il.mul(8, il.pop(8), il.pop(8))).append(),
            Op::Neg => il.push(8, il.neg(8, il.pop(8))).append(),
            Op::Not => il.push(8, il.not(8, il.pop(8))).append(),
            Op::Or => il.push(8, il.or(8, il.pop(8), il.pop(8))).append(),
            Op::Plus => il.push(8, il.add(8, il.pop(8), il.pop(8))).append(),
            Op::PlusConst(v) => il.push(8, il.add(8, il.pop(8), v)).append(),
            Op::Shl => {
                il.set_reg(8, llil::Register::Temp(0), il.pop(8)).append();
                il.set_reg(8, llil::Register::Temp(1), il.pop(8)).append();

                il.push(
                    8,
                    il.lsl(
                        8,
                        il.reg(8, llil::Register::Temp(1)),
                        il.reg(8, llil::Register::Temp(0)),
                    ),
                )
                .append();
            }
            Op::Shr => {
                il.set_reg(8, llil::Register::Temp(0), il.pop(8)).append();
                il.set_reg(8, llil::Register::Temp(1), il.pop(8)).append();

                il.push(
                    8,
                    il.lsr(
                        8,
                        il.reg(8, llil::Register::Temp(1)),
                        il.reg(8, llil::Register::Temp(0)),
                    ),
                )
                .append();
            }
            Op::Shra => {
                il.set_reg(8, llil::Register::Temp(0), il.pop(8)).append();
                il.set_reg(8, llil::Register::Temp(1), il.pop(8)).append();

                il.push(
                    8,
                    il.asr(
                        8,
                        il.reg(8, llil::Register::Temp(1)),
                        il.reg(8, llil::Register::Temp(0)),
                    ),
                )
                .append();
            }
            Op::Xor => il.push(8, il.xor(8, il.pop(8), il.pop(8))).append(),
            Op::Bra(off) => {
                let cond_expr = il.cmp_e(8, il.pop(8), 0u64);

                let mut new_false: Option<Label> = None;
                let mut new_true: Option<Label> = None;

                let ft = pc;
                let tt = pc.wrapping_add(off as i64 as u64);

                {
                    let f = il.label_for_address(ft).unwrap_or_else(|| {
                        new_false = Some(Label::new());
                        new_false.as_ref().unwrap()
                    });

                    let t = il.label_for_address(tt).unwrap_or_else(|| {
                        new_true = Some(Label::new());
                        new_true.as_ref().unwrap()
                    });

                    il.if_expr(cond_expr, t, f).append();
                }

                if let Some(t) = new_true.as_mut() {
                    il.mark_label(t);

                    il.jump(il.const_ptr(tt)).append();
                }

                if let Some(f) = new_false.as_mut() {
                    il.mark_label(f);
                }
            }
            Op::Eq => il.push(8, il.cmp_e(8, il.pop(8), il.pop(8))).append(),
            Op::Ge => il.push(8, il.cmp_uge(8, il.pop(8), il.pop(8))).append(),
            Op::Gt => il.push(8, il.cmp_ugt(8, il.pop(8), il.pop(8))).append(),
            Op::Le => il.push(8, il.cmp_ule(8, il.pop(8), il.pop(8))).append(),
            Op::Lt => il.push(8, il.cmp_ult(8, il.pop(8), il.pop(8))).append(),
            Op::Ne => il.push(8, il.cmp_ne(8, il.pop(8), il.pop(8))).append(),
            Op::Skip(off) => {
                let target = pc.wrapping_add(off as i64 as u64);

                match il.label_for_address(target) {
                    Some(l) => il.goto(l),
                    None => il.jump(il.const_ptr(target)),
                }
                .append();

                cont = false;
            }
            Op::Lit(v) => il.push(8, v as u64).append(),
            Op::Reg(r) => il.push(8, il.reg(8, Register::new(r.into()))).append(),
            Op::BReg(_, _) => todo!(),
            Op::RegX(_) => todo!(),
            Op::BRegX(_, _) => todo!(),
            Op::DerefSize(sz) => il.push(8, il.zx(8, il.load(sz, il.pop(8)))).append(),
            Op::Nop => il.nop().append(),
        };

        Some((sz, cont))
    }

    fn flag_write_llil<'a>(
        &self,
        _flag: Self::Flag,
        _flag_write: Self::FlagWrite,
        _op: llil::FlagWriteOp<Self::Register>,
        _il: &'a mut llil::Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
        None
    }

    fn flag_cond_llil<'a>(
        &self,
        _cond: FlagCondition,
        _class: Option<Self::Flag>,
        _il: &'a mut llil::Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
        None
    }

    fn flag_group_llil<'a>(
        &self,
        _group: Self::FlagGroup,
        _il: &'a mut llil::Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
        None
    }

    fn registers_all(&self) -> Vec<Self::Register> {
        (0..=MAX_REG_NO).map(|ii| Register::new(ii)).collect()
    }

    fn registers_full_width(&self) -> Vec<Self::Register> {
        self.registers_all()
    }

    fn registers_global(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn registers_system(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn flags(&self) -> Vec<Self::Flag> {
        Vec::new()
    }

    fn flag_write_types(&self) -> Vec<Self::FlagWrite> {
        Vec::new()
    }

    fn flag_classes(&self) -> Vec<Self::FlagClass> {
        Vec::new()
    }

    fn flag_groups(&self) -> Vec<Self::FlagGroup> {
        Vec::new()
    }

    fn flags_required_for_flag_condition(
        &self,
        _cond: FlagCondition,
        _class: Option<Flag>,
    ) -> Vec<Self::Flag> {
        Vec::new()
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register> {
        Some(Register::new(REG_SP))
    }

    fn link_reg(&self) -> Option<Self::Register> {
        Some(Register::new(REG_LR))
    }

    fn register_from_id(&self, id: u32) -> Option<Self::Register> {
        match id {
            0..=MAX_REG_NO => Some(Register::new(id)),
            _ => None,
        }
    }

    fn flag_from_id(&self, _id: u32) -> Option<Self::Flag> {
        None
    }

    fn flag_write_from_id(&self, _id: u32) -> Option<Self::FlagWrite> {
        None
    }

    fn flag_class_from_id(&self, _id: u32) -> Option<Self::FlagClass> {
        None
    }

    fn flag_group_from_id(&self, _id: u32) -> Option<Self::FlagGroup> {
        None
    }

    fn handle(&self) -> CustomArchitectureHandle<Self> {
        self.custom_handle
    }
}

impl AsRef<CoreArchitecture> for DwarfArch {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.handle
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    binja::logger::init(log::LevelFilter::Trace).expect("Failed to set up logging");

    architecture::register_architecture("DWARF", |custom_handle, core_arch| DwarfArch {
        handle: core_arch,
        custom_handle: custom_handle,
    });

    true
}
