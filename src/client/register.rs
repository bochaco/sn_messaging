// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, CmdError, DataAuthKind, Error, QueryResponse};
use serde::{Deserialize, Serialize};
use sn_data_types::{
    PublicKey, Register, RegisterAddress as Address, RegisterEntry as Entry,
    RegisterIndex as Index, RegisterOp, RegisterUser as User,
};
use std::fmt;
use xor_name::XorName;

/// TODO: docs
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum RegisterRead {
    /// Get Register from the network.
    Get(Address),
    /// Get a range of entries from an Register object on the network.
    GetRange {
        /// Register address.
        address: Address,
        /// Range of entries to fetch.
        ///
        /// For example, get 10 last entries:
        /// range: (Index::FromEnd(10), Index::FromEnd(0))
        ///
        /// Get all entries:
        /// range: (Index::FromStart(0), Index::FromEnd(0))
        ///
        /// Get first 5 entries:
        /// range: (Index::FromStart(0), Index::FromStart(5))
        range: (Index, Index),
    },
    /// Get last entry from the Register.
    GetLastEntry(Address),
    /// List current policy
    GetPublicPolicy(Address),
    /// List current policy
    GetPrivatePolicy(Address),
    /// Get current permissions for a specified user(s).
    GetUserPermissions {
        /// Register address.
        address: Address,
        /// User to get permissions for.
        user: User,
    },
    /// Get current owner.
    GetOwner(Address),
}

/// TODO: docs
#[allow(clippy::large_enum_variant)]
#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum RegisterWrite {
    /// Create a new Register on the network.
    New(Register),
    /// Edit the Register (insert/remove entry).
    Edit(RegisterOp<Entry>),
    /// Delete a private Register.
    ///
    /// This operation MUST return an error if applied to public Register. Only the current
    /// owner(s) can perform this action.
    Delete(Address),
}

impl RegisterRead {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> QueryResponse {
        use RegisterRead::*;
        match *self {
            Get(_) => QueryResponse::GetRegister(Err(error)),
            GetRange { .. } => QueryResponse::GetRegisterRange(Err(error)),
            GetLastEntry(_) => QueryResponse::GetRegisterLastEntry(Err(error)),
            GetPublicPolicy(_) => QueryResponse::GetRegisterPublicPolicy(Err(error)),
            GetPrivatePolicy(_) => QueryResponse::GetRegisterPrivatePolicy(Err(error)),
            GetUserPermissions { .. } => QueryResponse::GetRegisterUserPermissions(Err(error)),
            GetOwner(_) => QueryResponse::GetRegisterOwner(Err(error)),
        }
    }

    /// Returns the access categorisation of the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use RegisterRead::*;
        match *self {
            Get(address)
            | GetRange { address, .. }
            | GetLastEntry(address)
            | GetPublicPolicy(address)
            | GetPrivatePolicy(address)
            | GetUserPermissions { address, .. }
            | GetOwner(address) => {
                if address.is_public() {
                    AuthorisationKind::Data(DataAuthKind::PublicRead)
                } else {
                    AuthorisationKind::Data(DataAuthKind::PrivateRead)
                }
            }
        }
    }

    /// Returns the address of the destination for request.
    pub fn dst_address(&self) -> XorName {
        use RegisterRead::*;
        match self {
            Get(ref address)
            | GetRange { ref address, .. }
            | GetLastEntry(ref address)
            | GetPublicPolicy(ref address)
            | GetPrivatePolicy(ref address)
            | GetUserPermissions { ref address, .. }
            | GetOwner(ref address) => *address.name(),
        }
    }
}

impl fmt::Debug for RegisterRead {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use RegisterRead::*;
        write!(
            formatter,
            "RegisterRead::{}",
            match *self {
                Get(_) => "GetRegister",
                GetRange { .. } => "GetRegisterRange",
                GetLastEntry(_) => "GetRegisterLastEntry",
                GetPublicPolicy { .. } => "GetRegisterPublicPolicy",
                GetPrivatePolicy { .. } => "GetRegisterPrivatePolicy",
                GetUserPermissions { .. } => "GetUserPermissions",
                GetOwner { .. } => "GetOwner",
            }
        )
    }
}

impl RegisterWrite {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> CmdError {
        CmdError::Data(error)
    }

    /// Returns the access categorisation of the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        AuthorisationKind::Data(DataAuthKind::Write)
    }

    /// Returns the address of the destination for request.
    pub fn dst_address(&self) -> XorName {
        use RegisterWrite::*;
        match self {
            New(ref data) => *data.name(),
            Delete(ref address) => *address.name(),
            Edit(ref op) => *op.address.name(),
        }
    }

    /// Owner of the RegisterWrite
    pub fn owner(&self) -> Option<PublicKey> {
        match self {
            Self::New(data) => Some(data.owner()),
            _ => None,
        }
    }
}

impl fmt::Debug for RegisterWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use RegisterWrite::*;
        write!(
            formatter,
            "RegisterWrite::{}",
            match *self {
                New(_) => "NewRegister",
                Delete(_) => "DeleteRegister",
                Edit(_) => "EditRegister",
            }
        )
    }
}
