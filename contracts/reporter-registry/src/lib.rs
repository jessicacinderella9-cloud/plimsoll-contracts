//! Reporter registry: decides which addresses may post reserve reports and
//! supply snapshots to the coverage ledger, and in which role.
#![no_std]

use plimsoll_types::{
    PendingUpgrade, ReporterEntry, ReporterInfo, Role, DEFAULT_MAX_REPORTERS_PER_ASSET,
    INSTANCE_EXTEND_TO, INSTANCE_THRESHOLD, PERSISTENT_EXTEND_TO, PERSISTENT_THRESHOLD,
    UPGRADE_DELAY_LEDGERS,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    BytesN, ContractExecutable, Env, String, Vec,
};

const MAX_NAME_LEN: u32 = 64;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Reporter(Address),
    PendingUpgrade,
    MaxReporters,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RegistryError {
    ReporterNotFound = 1,
    InvalidName = 2,
    UpgradeNotProposed = 3,
    UpgradeDelayNotElapsed = 4,
    InvalidMaxReporters = 5,
    EmptyBatch = 6,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterSet {
    #[topic]
    pub reporter: Address,
    pub role: Role,
    pub name: String,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterRevoked {
    #[topic]
    pub reporter: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferred {
    #[topic]
    pub new_admin: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaxReportersSet {
    #[topic]
    pub max: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposed {
    #[topic]
    pub wasm_hash: BytesN<32>,
    pub executable_at_ledger: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeExecuted {
    #[topic]
    pub wasm_hash: BytesN<32>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeCancelled {
    #[topic]
    pub wasm_hash: BytesN<32>,
}

#[contract]
pub struct ReporterRegistry;

fn admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("admin is set in the constructor")
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_THRESHOLD, INSTANCE_EXTEND_TO);
}

fn pending(env: &Env) -> Option<PendingUpgrade> {
    env.storage().instance().get(&DataKey::PendingUpgrade)
}

/// The admin's per-asset reporter cap, or `DEFAULT_MAX_REPORTERS_PER_ASSET`
/// while it has not been set. A registry upgraded from v0.1 has no stored
/// value, so it answers the default without a migration.
fn configured_max_reporters(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::MaxReporters)
        .unwrap_or(DEFAULT_MAX_REPORTERS_PER_ASSET)
}

fn require_valid_name(env: &Env, name: &String) {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        panic_with_error!(env, RegistryError::InvalidName);
    }
}

/// Add a reporter, or change an existing reporter's role and name. Used by
/// both the single and the batch entry point, so the two can never drift.
fn write_reporter(env: &Env, reporter: &Address, role: Role, name: &String) {
    let key = DataKey::Reporter(reporter.clone());
    let added_at = env
        .storage()
        .persistent()
        .get::<_, ReporterInfo>(&key)
        .map(|existing| existing.added_at)
        .unwrap_or_else(|| env.ledger().timestamp());
    let info = ReporterInfo {
        role,
        name: name.clone(),
        added_at,
    };
    env.storage().persistent().set(&key, &info);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
    ReporterSet {
        reporter: reporter.clone(),
        role,
        name: name.clone(),
    }
    .publish(env);
}

#[contractimpl]
impl ReporterRegistry {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        bump_instance(&env);
    }

    pub fn admin(env: Env) -> Address {
        admin(&env)
    }

    /// Add a reporter, or change an existing reporter's role and name.
    pub fn set_reporter(env: Env, reporter: Address, role: Role, name: String) {
        admin(&env).require_auth();
        require_valid_name(&env, &name);
        write_reporter(&env, &reporter, role, &name);
        bump_instance(&env);
    }

    /// Add or change many reporters in one transaction, so populating the
    /// registry does not take a transaction per reporter.
    ///
    /// Every entry is validated before the first one is written, and a failed
    /// call reverts the whole transaction, so the batch is all or nothing. The
    /// per-asset cap (`max_reporters`) is not a registry rule -- the registry
    /// does not know which assets a reporter will speak for -- so the coverage
    /// ledger applies it at post time and a batch cannot register its way past
    /// it.
    pub fn batch_register(env: Env, reporters: Vec<ReporterEntry>) {
        admin(&env).require_auth();
        if reporters.is_empty() {
            panic_with_error!(&env, RegistryError::EmptyBatch);
        }
        for entry in reporters.iter() {
            require_valid_name(&env, &entry.name);
        }
        for entry in reporters.iter() {
            write_reporter(&env, &entry.reporter, entry.role, &entry.name);
        }
        bump_instance(&env);
    }

    pub fn revoke(env: Env, reporter: Address) {
        admin(&env).require_auth();
        let key = DataKey::Reporter(reporter.clone());
        if !env.storage().persistent().has(&key) {
            panic_with_error!(&env, RegistryError::ReporterNotFound);
        }
        env.storage().persistent().remove(&key);
        bump_instance(&env);
        ReporterRevoked { reporter }.publish(&env);
    }

    pub fn role_of(env: Env, reporter: Address) -> Option<Role> {
        Self::get_reporter(env, reporter).map(|info| info.role)
    }

    pub fn get_reporter(env: Env, reporter: Address) -> Option<ReporterInfo> {
        let key = DataKey::Reporter(reporter);
        let info = env.storage().persistent().get::<_, ReporterInfo>(&key);
        if info.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        }
        info
    }

    /// The registry-level cap on how many reporters one asset may hold. The
    /// coverage ledger reads it when a reporter posts for an asset for the
    /// first time.
    pub fn max_reporters(env: Env) -> u32 {
        configured_max_reporters(&env)
    }

    /// Set the per-asset reporter cap. Zero would stop every asset taking a
    /// new reporter, so it is refused; one is the tightest useful setting.
    pub fn set_max_reporters(env: Env, max: u32) {
        admin(&env).require_auth();
        if max == 0 {
            panic_with_error!(&env, RegistryError::InvalidMaxReporters);
        }
        env.storage().instance().set(&DataKey::MaxReporters, &max);
        bump_instance(&env);
        MaxReportersSet { max }.publish(&env);
    }

    pub fn transfer_admin(env: Env, new_admin: Address) {
        admin(&env).require_auth();
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        bump_instance(&env);
        AdminTransferred { new_admin }.publish(&env);
    }

    /// Propose a wasm hash for installation after the upgrade delay. A new
    /// proposal replaces any pending one and restarts the clock.
    pub fn propose_upgrade(env: Env, wasm_hash: BytesN<32>) {
        admin(&env).require_auth();
        let executable_at_ledger = env
            .ledger()
            .sequence()
            .saturating_add(UPGRADE_DELAY_LEDGERS);
        env.storage().instance().set(
            &DataKey::PendingUpgrade,
            &PendingUpgrade {
                wasm_hash: wasm_hash.clone(),
                executable_at_ledger,
            },
        );
        bump_instance(&env);
        UpgradeProposed {
            wasm_hash,
            executable_at_ledger,
        }
        .publish(&env);
    }

    /// Install the pending wasm once its delay has elapsed.
    pub fn execute_upgrade(env: Env) {
        admin(&env).require_auth();
        let proposed = match pending(&env) {
            Some(proposed) => proposed,
            None => panic_with_error!(&env, RegistryError::UpgradeNotProposed),
        };
        if env.ledger().sequence() < proposed.executable_at_ledger {
            panic_with_error!(&env, RegistryError::UpgradeDelayNotElapsed);
        }
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        bump_instance(&env);
        UpgradeExecuted {
            wasm_hash: proposed.wasm_hash.clone(),
        }
        .publish(&env);
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(proposed.wasm_hash));
    }

    /// Cancel the pending upgrade.
    pub fn cancel_upgrade(env: Env) {
        admin(&env).require_auth();
        let proposed = match pending(&env) {
            Some(proposed) => proposed,
            None => panic_with_error!(&env, RegistryError::UpgradeNotProposed),
        };
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        bump_instance(&env);
        UpgradeCancelled {
            wasm_hash: proposed.wasm_hash,
        }
        .publish(&env);
    }

    /// The pending upgrade, if any.
    pub fn pending_upgrade(env: Env) -> Option<PendingUpgrade> {
        let proposed = pending(&env);
        if proposed.is_some() {
            bump_instance(&env);
        }
        proposed
    }
}

#[cfg(test)]
mod test;
