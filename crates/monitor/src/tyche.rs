use arena::Handle;
use capabilities::access::AccessRights;
use capabilities::backend::Backend;
use capabilities::context::Context;
use capabilities::cpu::CPU;
use capabilities::domain::{Domain, DomainAccess, OwnedCapability};
use capabilities::error::ErrorCode;
use capabilities::{Capability, CapabilityType, Object, Pool};

use crate::{Monitor, MonitorCallResult, MonitorState, Parameters, Registers};

// ————————————————————————————————— Tyche —————————————————————————————————— //
pub struct Tyche {}

/// Valid monitor calls for the tyche profile.
pub type TycheCall = usize;

/// List of valid monitor calls.
pub const TYCHE_CREATE_DOMAIN: TycheCall = 1;
pub const TYCHE_SEAL_DOMAIN: TycheCall = 2;
pub const TYCHE_SHARE: TycheCall = 3;
pub const TYCHE_GRANT: TycheCall = 4;
pub const TYCHE_GIVE: TycheCall = 5;
pub const TYCHE_REVOKE: TycheCall = 6;
pub const TYCHE_ENUMERATE: TycheCall = 7;
pub const TYCHE_SWITCH: TycheCall = 8;
pub const TYCHE_EXIT: TycheCall = 9;

// For enumeration
pub const TYCHE_DOMAIN_TYPE: usize = 0;
pub const TYCHE_REGION_TYPE: usize = 1;
pub const TYCHE_CPU_TYPE: usize = 2;

// For transition
pub const CPU_LOCAL_TRANSITION: usize = usize::MAX;

impl<B: Backend> Monitor<B> for Tyche {
    type MonitorCall = TycheCall;
    fn is_exit(&self, _state: &MonitorState<B>, params: &Parameters) -> bool {
        params.vmcall == TYCHE_EXIT
    }

    fn dispatch(&self, state: &mut MonitorState<B>, params: &Parameters) -> MonitorCallResult<B> {
        match params.vmcall {
            TYCHE_CREATE_DOMAIN => self.create_domain(state, params.arg_1, params.arg_2),
            TYCHE_SEAL_DOMAIN => self.seal_domain(
                state,
                params.arg_1,
                params.arg_2,
                params.arg_3,
                params.arg_4,
                params.arg_5,
            ),
            TYCHE_SHARE => self.share_grant(
                true,
                state,
                params.arg_1,
                params.arg_2,
                params.arg_3,
                params.arg_4,
                params.arg_5,
            ),
            TYCHE_GRANT => self.share_grant(
                false,
                state,
                params.arg_1,
                params.arg_2,
                params.arg_3,
                params.arg_4,
                params.arg_5,
            ),
            TYCHE_GIVE => self.transfer(state, params.arg_1, params.arg_2),
            TYCHE_REVOKE => self.revoke(state, params.arg_1),
            TYCHE_ENUMERATE => self.enumerate(state, params.arg_1),
            TYCHE_SWITCH => self.switch(state, params.arg_1, params.arg_2),
            TYCHE_EXIT => panic!("Exit should not reach dispatch."),
            _ => panic!("Unknown MonitorCall in Tyche: 0x{:x}", params.vmcall),
        }
    }
}

impl Tyche {
    pub fn create_domain<B: Backend>(
        &self,
        state: &mut MonitorState<B>,
        spawn: usize,
        comm: usize,
    ) -> MonitorCallResult<B> {
        let revocation = { state.get_current_domain().get_local_idx()? };
        let (orig, new_domain) = {
            let mut current = state.get_current_domain();
            let new_access = DomainAccess::Unsealed(spawn == 1, comm == 1);
            let access = current.access;
            current.duplicate(access, new_access, &state.resources)?
        };
        // Patch up the current domain.
        let orig_idx = {
            state.set_current_domain(orig);
            let orig_capa = state.resources.get_capa(orig);
            orig_capa.get_local_idx()?
        };
        let new_domain_idx = {
            let new_domain_capa = state.resources.get_capa(new_domain);
            new_domain_capa.get_local_idx()?
        };
        // Return the local idx, not the pool ones.
        Ok(Registers {
            value_1: orig_idx,
            value_2: new_domain_idx,
            value_3: revocation,
            ..Default::default()
        })
    }

    pub fn seal_domain<B: Backend>(
        &self,
        state: &MonitorState<B>,
        dom_idx: usize,
        core_map: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    ) -> MonitorCallResult<B> {
        let current = state.get_current_domain();

        let handle = match *state
            .resources
            .get(current.handle)
            .get_local_capa(dom_idx)
            .map_err(|e| e.wrap())?
        {
            OwnedCapability::Domain(handle) => handle,
            _ => {
                return ErrorCode::InvalidLocalCapa.as_err();
            }
        };
        let dom = state.resources.get_capa(handle).handle;
        state.resources.transfer(handle, dom)?;
        let trans = state
            .resources
            .get_capa_mut(handle)
            .seal(&state.resources, core_map, arg1, arg2, arg3)
            .map_err(|e| e.wrap())?;
        // Now transfer the transition capability to the current domain.
        state.resources.transfer(trans, current.handle)?;
        let local_id = state.resources.get_capa(trans).get_local_idx()?;
        Ok(Registers {
            value_1: local_id,
            ..Default::default()
        })
    }

    pub fn get_target<B: Backend>(
        &self,
        state: &MonitorState<B>,
        tgt_idx: usize,
    ) -> Result<Handle<Domain<B>>, ErrorCode> {
        let current = state.get_current_domain();
        let idx = match *state
            .resources
            .get(current.handle)
            .get_local_capa(tgt_idx)?
        {
            OwnedCapability::Domain(h) => {
                let capa = state.resources.get_capa(h);
                match capa.access {
                    // We do not need to check the comm.
                    DomainAccess::Unsealed(_, _) => capa.handle,
                    DomainAccess::Channel => capa.handle,
                    _ => {
                        return Err(ErrorCode::InvalidTransfer);
                    }
                }
            }
            _ => {
                return Err(ErrorCode::InvalidTransfer);
            }
        };
        Ok(idx)
    }

    pub fn transfer<B: Backend>(
        &self,
        state: &MonitorState<B>,
        tgt_idx: usize,
        idx: usize,
    ) -> MonitorCallResult<B> {
        let target = self.get_target(state, tgt_idx).map_err(|e| e.wrap())?;
        let current = state.get_current_domain().handle;
        match *state
            .resources
            .get(current)
            .get_local_capa(idx)
            .map_err(|e| e.wrap())?
        {
            // Easy cases
            OwnedCapability::CPU(h) => {
                state.resources.transfer(h, target)?;
            }
            OwnedCapability::Region(h) => {
                state.resources.transfer(h, target)?;
            }
            // Cases with checks
            OwnedCapability::Domain(h) => {
                {
                    let domain_capa = state.resources.get_capa(h);
                    match domain_capa.access {
                        DomainAccess::Unsealed(_, _) => {}
                        DomainAccess::Channel => {}
                        _ => {
                            return ErrorCode::InvalidTransfer.as_err();
                        }
                    }
                }
                state.resources.transfer(h, target)?;
            }
            _ => {
                return ErrorCode::InvalidTransfer.as_err();
            }
        };
        Ok(Registers {
            ..Default::default()
        })
    }

    pub fn share_grant<B: Backend>(
        &self,
        is_share: bool,
        state: &MonitorState<B>,
        tgt_idx: usize,
        capa_idx: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    ) -> MonitorCallResult<B> {
        let target = self.get_target(state, tgt_idx).map_err(|e| e.wrap())?;
        let current = state.get_current_domain().handle;
        match *state
            .resources
            .get(current)
            .get_local_capa(capa_idx)
            .map_err(|e| e.wrap())?
        {
            OwnedCapability::CPU(h) => {
                self.share_grant_inner(is_share, &state.resources, h, target, arg1, arg2, arg3)
            }
            OwnedCapability::Region(h) => {
                self.share_grant_inner(is_share, &state.resources, h, target, arg1, arg2, arg3)
            }
            OwnedCapability::Domain(h) => match state.resources.get_capa(h).access {
                DomainAccess::Channel => {
                    self.share_grant_inner(is_share, &state.resources, h, target, arg1, arg2, arg3)
                }
                _ => {
                    return ErrorCode::InvalidShareGrant.as_err();
                }
            },
            _ => {
                return ErrorCode::InvalidShareGrant.as_err();
            }
        }
    }

    fn share_grant_inner<O: Object, B: Backend>(
        &self,
        is_share: bool,
        pool: &impl Pool<O, B = B>,
        handle: Handle<Capability<O>>,
        target: Handle<Domain<B>>,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    ) -> MonitorCallResult<B> {
        let orig_idx = { pool.get_capa(handle).get_local_idx()? };
        let mut capa = pool.get_capa_mut(handle);
        let access = if is_share {
            capa.access
        } else {
            O::Access::get_null()
        };
        let (left, right) = capa.duplicate(access, O::from_bits(arg1, arg2, arg3), pool)?;
        pool.transfer(right, target)?;
        let left_idx = {
            if is_share {
                pool.get_capa(left).get_local_idx()?
            } else {
                // In case of a grant, the left is null and not installed.
                orig_idx
            }
        };
        Ok(Registers {
            value_1: left_idx,
            ..Default::default()
        })
    }

    pub fn revoke<B: Backend>(
        &self,
        state: &MonitorState<B>,
        capa_idx: usize,
    ) -> MonitorCallResult<B> {
        let current = state.get_current_domain().handle;
        // We might have to access the object domain itself, so we need to do
        // this in two steps to avoid double borrow.
        let owned = match *state
            .resources
            .get(current)
            .get_local_capa(capa_idx)
            .map_err(|e| e.wrap())?
        {
            OwnedCapability::CPU(h) => OwnedCapability::CPU(h),
            OwnedCapability::Region(h) => OwnedCapability::Region(h),
            OwnedCapability::Domain(h) => OwnedCapability::Domain(h),
            _ => {
                return ErrorCode::InvalidRevocation.as_err();
            }
        };
        // Now that we don't have a reference on the object itself, we can
        // safely call the revoke function.
        match owned {
            OwnedCapability::CPU(h) => {
                state.resources.get_capa_mut(h).revoke(&state.resources)?;
            }
            OwnedCapability::Region(h) => {
                state.resources.get_capa_mut(h).revoke(&state.resources)?
            }
            OwnedCapability::Domain(h) => {
                state.resources.get_capa_mut(h).revoke(&state.resources)?
            }
            _ => {
                return ErrorCode::InvalidRevocation.as_err();
            }
        }
        Ok(Registers {
            ..Default::default()
        })
    }

    fn enumerate<B: Backend>(
        &self,
        state: &MonitorState<B>,
        capa_idx: usize,
    ) -> MonitorCallResult<B> {
        let curr_handle = state.get_current_domain().handle;
        let current = state.resources.get(curr_handle);
        let res = current
            .enumerate_at(
                capa_idx,
                |idx, own| -> (usize, usize, usize, usize, usize, usize) {
                    match *own {
                        OwnedCapability::Domain(h) => {
                            let capa = state.resources.get_capa(h);
                            let obj = state.resources.get(capa.handle);
                            let (b1, b2, b3) = capa.access.as_bits();
                            let ref_count = obj.get_ref(&state.resources, &capa);
                            return (idx, TYCHE_DOMAIN_TYPE, b1, b2, b3, ref_count);
                        }
                        OwnedCapability::CPU(h) => {
                            let capa = state.resources.get_capa(h);
                            let obj = state.resources.get(capa.handle);
                            let (b1, b2, b3) = capa.access.as_bits();
                            let ref_count = obj.get_ref(&state.resources, &capa);
                            return (idx, TYCHE_CPU_TYPE, b1, b2, b3, ref_count);
                        }
                        OwnedCapability::Region(h) => {
                            let capa = state.resources.get_capa(h);
                            let obj = state.resources.get(capa.handle);
                            let (b1, b2, b3) = capa.access.as_bits();
                            let ref_count = obj.get_ref(&state.resources, &capa);
                            return (idx, TYCHE_REGION_TYPE, b1, b2, b3, ref_count);
                        }
                        _ => {
                            return (
                                usize::MAX,
                                usize::MAX,
                                usize::MAX,
                                usize::MAX,
                                usize::MAX,
                                usize::MAX,
                            )
                        }
                    };
                },
            )
            .map_err(|e| e.wrap())?;
        if res.0 == usize::MAX {
            return ErrorCode::OutOfBound.as_err();
        }
        Ok(Registers {
            value_1: res.0,
            value_2: res.1,
            value_3: res.2,
            value_4: res.3,
            value_5: res.4,
            value_6: res.5,
            ..Default::default()
        })
    }

    fn switch<B: Backend>(
        &self,
        state: &mut MonitorState<B>,
        handle: usize,
        cpu: usize,
    ) -> MonitorCallResult<B> {
        if cpu == CPU_LOCAL_TRANSITION {
            self.switch_internal(state, handle, state.get_current_cpu_handle())
        } else {
            let cpu_h = {
                let dom_h = state.get_current_domain().handle;
                let dom = state.resources.get(dom_h);
                let h = dom
                    .get_local_capa(cpu)
                    .map_err(|e| e.wrap())?
                    .as_cpu()
                    .map_err(|e| e.wrap())?;
                h
            };
            self.switch_internal(state, handle, cpu_h)
        }
    }

    fn switch_internal<B: Backend>(
        &self,
        state: &mut MonitorState<B>,
        handle: usize,
        cpu: Handle<Capability<CPU<B>>>,
    ) -> MonitorCallResult<B> {
        // Check the handle points to a transition.
        let (target, target_ctxt, invoked_trans): (
            Handle<Domain<B>>,
            Handle<Context<B>>,
            Handle<Capability<Domain<B>>>,
        ) = {
            let curr_handle = state.get_current_domain().handle;
            let current = state.resources.get(curr_handle);
            let transition_h = current
                .get_local_capa(handle)
                .map_err(|e| e.wrap())?
                .as_domain()
                .map_err(|e| e.wrap())?;
            let transition = state.resources.get_capa(transition_h);
            let (dom_h, x) = match transition.access {
                DomainAccess::Transition(x) => (transition.handle, x),
                _ => {
                    return Err(ErrorCode::InvalidTransition.wrap());
                }
            };
            // Check the target domain is sealed and the transition is valid.
            let dom = state.resources.get(dom_h);
            if !dom.is_sealed() {
                return Err(ErrorCode::InvalidTransition.wrap());
            }
            if !dom.contexts.is_allocated(x) {
                return Err(ErrorCode::InvalidTransition.wrap());
            }
            // Check the domain can run on the current core.
            {
                let curr_cpu_h = state.resources.get_capa(cpu).handle;
                let curr_cpu = state.resources.get(curr_cpu_h);
                if !dom.is_allowed_core(curr_cpu.id) {
                    return Err(ErrorCode::InvalidTransition.wrap());
                }
            }
            (dom_h, Handle::new_unchecked(x), transition_h)
        };

        // Pause the invoked transition capability.
        {
            let mut invoked = state.resources.get_capa_mut(invoked_trans);
            invoked.duplicate(
                DomainAccess::get_null(),
                DomainAccess::get_null(),
                &state.resources,
            )?;
        }

        // Check if we have a defined transition target.
        // TODO handle cpu here as well.
        let return_capa_h = {
            let tgt = state.resources.get(target);
            let context = tgt.contexts.get(target_ctxt);
            match context.return_context {
                Some(return_handle) => {
                    // Check the return handle is correct.
                    let mut return_capa = state.resources.get_capa_mut(return_handle);

                    // This should point to the current domain.
                    if return_capa.handle != state.get_current_domain().handle {
                        return Err(ErrorCode::InvalidTransition.wrap());
                    }
                    // If this capability does not belong to the target
                    if return_capa.get_owner()? != target {
                        return Err(ErrorCode::InvalidTransition.wrap());
                    }

                    match (return_capa.access, return_capa.capa_type) {
                        (DomainAccess::Transition(_), CapabilityType::Revocation) => {
                            // Revoke the capability.
                            return_capa.revoke(&state.resources)?;
                            return_handle
                        }
                        (_, _) => {
                            return Err(ErrorCode::InvalidTransition.wrap());
                        }
                    }
                }
                None => {
                    // Allocate a local transition handle.
                    let (_, trans) = {
                        let mut curr_capa = state.get_current_domain();
                        curr_capa
                            .create_transition(&state.resources)
                            .map_err(|e| e.wrap())?
                    };
                    // Transfer it to the other domain.
                    state.resources.transfer(trans, target)?;
                    trans
                }
            }
        };

        // Patch the return capa to point to the paused transition.
        {
            let return_capa = state.resources.get_capa(return_capa_h);
            let idx = if let DomainAccess::Transition(y) = return_capa.access {
                y
            } else {
                return Err(ErrorCode::InvalidTransition.wrap());
            };
            let current_h = state.get_current_domain().handle;
            let current = state.resources.get(current_h);
            let mut to_patch = current.contexts.get_mut(Handle::new_unchecked(idx));
            to_patch.return_context = Some(invoked_trans);
        }

        // Transfer the cpu to the target domain.
        // TODO: Update when we handle multiple vcpu
        state.resources.transfer(cpu, target)?;

        // Apply the backend switch.
        let curr_h = state.get_current_domain().handle;
        state.resources.backend.switch_context(
            &state.resources,
            curr_h,
            target,
            return_capa_h,
            invoked_trans,
            cpu,
        )?;

        // Get the target sealed capability.
        let tgt_sealed = {
            let domain = state.resources.get(target);
            domain.get_sealed_capa().map_err(|e| e.wrap())?
        };
        state.set_current_domain(tgt_sealed);
        state.set_current_cpu(cpu);

        let local_return_idx = {
            let capa = state.resources.get_capa(return_capa_h);
            capa.get_local_idx()?
        };

        Ok(Registers {
            value_1: local_return_idx,
            ..Default::default()
        })
    }
}
