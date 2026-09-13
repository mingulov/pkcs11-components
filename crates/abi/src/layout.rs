//! Allocation-free PKCS#11 function-table layout facts for Linux LP64 and ILP32.
//!
//! These operations describe target memory. They do not depend on the observer's
//! pointer width and do not select or dereference a provider interface.

/// The single ordered catalog of standard function-list fields.
macro_rules! function_catalog {
    ($consumer:ident) => {
        $consumer! {
            base [
            C_Initialize,
            C_Finalize,
            C_GetInfo,
            C_GetFunctionList,
            C_GetSlotList,
            C_GetSlotInfo,
            C_GetTokenInfo,
            C_GetMechanismList,
            C_GetMechanismInfo,
            C_InitToken,
            C_InitPIN,
            C_SetPIN,
            C_OpenSession,
            C_CloseSession,
            C_CloseAllSessions,
            C_GetSessionInfo,
            C_GetOperationState,
            C_SetOperationState,
            C_Login,
            C_Logout,
            C_CreateObject,
            C_CopyObject,
            C_DestroyObject,
            C_GetObjectSize,
            C_GetAttributeValue,
            C_SetAttributeValue,
            C_FindObjectsInit,
            C_FindObjects,
            C_FindObjectsFinal,
            C_EncryptInit,
            C_Encrypt,
            C_EncryptUpdate,
            C_EncryptFinal,
            C_DecryptInit,
            C_Decrypt,
            C_DecryptUpdate,
            C_DecryptFinal,
            C_DigestInit,
            C_Digest,
            C_DigestUpdate,
            C_DigestKey,
            C_DigestFinal,
            C_SignInit,
            C_Sign,
            C_SignUpdate,
            C_SignFinal,
            C_SignRecoverInit,
            C_SignRecover,
            C_VerifyInit,
            C_Verify,
            C_VerifyUpdate,
            C_VerifyFinal,
            C_VerifyRecoverInit,
            C_VerifyRecover,
            C_DigestEncryptUpdate,
            C_DecryptDigestUpdate,
            C_SignEncryptUpdate,
            C_DecryptVerifyUpdate,
            C_GenerateKey,
            C_GenerateKeyPair,
            C_WrapKey,
            C_UnwrapKey,
            C_DeriveKey,
            C_SeedRandom,
            C_GenerateRandom,
            C_GetFunctionStatus,
            C_CancelFunction,
            C_WaitForSlotEvent,
            ]
            v3_0 [
            C_GetInterfaceList,
            C_GetInterface,
            C_LoginUser,
            C_SessionCancel,
            C_MessageEncryptInit,
            C_EncryptMessage,
            C_EncryptMessageBegin,
            C_EncryptMessageNext,
            C_MessageEncryptFinal,
            C_MessageDecryptInit,
            C_DecryptMessage,
            C_DecryptMessageBegin,
            C_DecryptMessageNext,
            C_MessageDecryptFinal,
            C_MessageSignInit,
            C_SignMessage,
            C_SignMessageBegin,
            C_SignMessageNext,
            C_MessageSignFinal,
            C_MessageVerifyInit,
            C_VerifyMessage,
            C_VerifyMessageBegin,
            C_VerifyMessageNext,
            C_MessageVerifyFinal,
            ]
            v3_2 [
            C_EncapsulateKey,
            C_DecapsulateKey,
            C_VerifySignatureInit,
            C_VerifySignature,
            C_VerifySignatureUpdate,
            C_VerifySignatureFinal,
            C_GetSessionValidationFlags,
            C_AsyncComplete,
            C_AsyncGetID,
            C_AsyncJoin,
            C_WrapKeyAuthenticated,
            C_UnwrapKeyAuthenticated,
            ]
        }
    };
}
pub(crate) use function_catalog;

macro_rules! define_names {
    (base [$($base:ident,)*] v3_0 [$($v3:ident,)*] v3_2 [$($v32:ident,)*]) => {
        /// All standard function names in table order. The slice index is the ordinal.
        pub static FUNCTION_NAMES: &[&str] = &[
            $(stringify!($base),)*
            $(stringify!($v3),)*
            $(stringify!($v32),)*
        ];
    };
}
function_catalog!(define_names);

/// A supported little-endian Linux PKCS#11 data model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxLayout {
    Lp64,
    Ilp32,
}

impl LinuxLayout {
    /// Size in bytes of a pointer and `CK_ULONG` in this data model.
    pub const fn word_bytes(self) -> usize {
        match self {
            Self::Lp64 => 8,
            Self::Ilp32 => 4,
        }
    }

    const fn function_base(self) -> usize {
        self.word_bytes()
    }

    /// Layout of one `CK_INTERFACE` entry: name pointer, function-list pointer, flags.
    pub const fn interface(self) -> InterfaceLayout {
        let width = self.word_bytes();
        InterfaceLayout {
            name_offset: 0,
            function_list_offset: width,
            flags_offset: width * 2,
            stride: width * 3,
        }
    }
}

/// Byte offsets and total stride of one `CK_INTERFACE` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceLayout {
    pub name_offset: usize,
    pub function_list_offset: usize,
    pub flags_offset: usize,
    pub stride: usize,
}

/// Failure while calculating or reading a target layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    FieldOutOfRange,
    OffsetOverflow,
    Truncated,
}

/// Return the name for an ordinal in the shared 104-field catalog.
pub fn function_name(ordinal: usize) -> Option<&'static str> {
    FUNCTION_NAMES.get(ordinal).copied()
}

/// Return a target byte offset for a function-pointer ordinal.
pub fn function_offset(layout: LinuxLayout, ordinal: usize) -> Result<usize, LayoutError> {
    if ordinal >= FUNCTION_NAMES.len() {
        return Err(LayoutError::FieldOutOfRange);
    }
    ordinal
        .checked_mul(layout.word_bytes())
        .and_then(|n| layout.function_base().checked_add(n))
        .ok_or(LayoutError::OffsetOverflow)
}

/// Return the exact target bytes occupied by a known function-list prefix.
pub fn table_bytes(layout: LinuxLayout, fields: usize) -> Result<usize, LayoutError> {
    if fields > FUNCTION_NAMES.len() {
        return Err(LayoutError::FieldOutOfRange);
    }
    fields
        .checked_mul(layout.word_bytes())
        .and_then(|n| layout.function_base().checked_add(n))
        .ok_or(LayoutError::OffsetOverflow)
}

/// Read one complete little-endian target word, zero-extending ILP32 words to `u64`.
pub fn read_word_le(bytes: &[u8], layout: LinuxLayout, offset: usize) -> Result<u64, LayoutError> {
    let end = offset.checked_add(layout.word_bytes()).ok_or(LayoutError::OffsetOverflow)?;
    let word = bytes.get(offset..end).ok_or(LayoutError::Truncated)?;
    Ok(match layout {
        LinuxLayout::Lp64 => {
            u64::from_le_bytes(word.try_into().map_err(|_| LayoutError::Truncated)?)
        }
        LinuxLayout::Ilp32 => {
            u32::from_le_bytes(word.try_into().map_err(|_| LayoutError::Truncated)?) as u64
        }
    })
}

/// Read a complete function pointer by ordinal from a target snapshot.
pub fn read_function_pointer(
    bytes: &[u8],
    layout: LinuxLayout,
    ordinal: usize,
) -> Result<u64, LayoutError> {
    read_word_le(bytes, layout, function_offset(layout, ordinal)?)
}

/// A PKCS#11 major/minor version used for table-prefix selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

/// Caller-asserted route by which a function table was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    LegacyFunctionList,
    StandardInterface,
}

/// Result of selecting the safely understood portion of a function table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// The complete reported layout is known and contains this many fields.
    Exact(usize),
    /// This many leading fields are known; later fields must not be read.
    KnownPrefix(usize),
    /// The version/provenance combination is not safe to inspect.
    Refuse,
}

/// Bind validated version and provenance to the safe function-list prefix.
pub const fn select(provenance: Provenance, version: Version) -> Selection {
    match provenance {
        Provenance::LegacyFunctionList => match (version.major, version.minor) {
            (2, 0) => Selection::Exact(67),
            (2, 1 | 10 | 11 | 20 | 30 | 40) => Selection::Exact(68),
            (2, _) | (3, _) => Selection::KnownPrefix(68),
            _ => Selection::Refuse,
        },
        Provenance::StandardInterface => match (version.major, version.minor) {
            (2, 40) => Selection::Exact(68),
            (2, _) => Selection::Refuse,
            (3, 0) | (3, 1) => Selection::Exact(92),
            (3, 2) => Selection::Exact(104),
            (3, _) => Selection::KnownPrefix(104),
            _ => Selection::Refuse,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_104_unique_ordered_names() {
        assert_eq!(FUNCTION_NAMES.len(), 104);
        for (ordinal, name) in FUNCTION_NAMES.iter().enumerate() {
            assert!(!FUNCTION_NAMES[..ordinal].contains(name), "duplicate {name}");
        }
        assert_eq!(function_name(0), Some("C_Initialize"));
        assert_eq!(function_name(67), Some("C_WaitForSlotEvent"));
        assert_eq!(function_name(68), Some("C_GetInterfaceList"));
        assert_eq!(function_name(91), Some("C_MessageVerifyFinal"));
        assert_eq!(function_name(92), Some("C_EncapsulateKey"));
        assert_eq!(function_name(103), Some("C_UnwrapKeyAuthenticated"));
        assert_eq!(function_name(104), None);
    }

    #[test]
    fn linux_prefix_sizes_and_offsets_are_checked() {
        for (layout, expected) in
            [(LinuxLayout::Lp64, [544, 552, 744, 840]), (LinuxLayout::Ilp32, [272, 276, 372, 420])]
        {
            for (fields, bytes) in [67, 68, 92, 104].into_iter().zip(expected) {
                assert_eq!(table_bytes(layout, fields), Ok(bytes));
            }
            assert_eq!(function_offset(layout, 0), Ok(layout.word_bytes()));
            assert_eq!(function_offset(layout, 103), Ok(expected[3] - layout.word_bytes()));
        }
        assert_eq!(function_offset(LinuxLayout::Lp64, 104), Err(LayoutError::FieldOutOfRange));
        assert_eq!(table_bytes(LinuxLayout::Ilp32, 105), Err(LayoutError::FieldOutOfRange));
    }

    #[test]
    fn reads_only_complete_words_and_zero_extends_ilp32() {
        let bytes = [0, 0, 0, 0, 0x78, 0x56, 0x34, 0xF2];
        assert_eq!(read_function_pointer(&bytes, LinuxLayout::Ilp32, 0), Ok(0xF234_5678));
        assert_eq!(read_word_le(&bytes[..7], LinuxLayout::Ilp32, 4), Err(LayoutError::Truncated));
        assert_eq!(
            read_word_le(&[], LinuxLayout::Lp64, usize::MAX),
            Err(LayoutError::OffsetOverflow)
        );

        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let len = table_bytes(layout, 104).unwrap();
            let mut table = [0u8; 840];
            let last = function_offset(layout, 103).unwrap();
            table[last..len].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8][..layout.word_bytes()]);
            let expected = match layout {
                LinuxLayout::Lp64 => 0x0807_0605_0403_0201,
                LinuxLayout::Ilp32 => 0x0403_0201,
            };
            assert_eq!(read_function_pointer(&table[..len], layout, 103), Ok(expected));
            assert_eq!(
                read_function_pointer(&table[..len - 1], layout, 103),
                Err(LayoutError::Truncated)
            );
        }
    }

    #[test]
    fn interface_layout_is_target_sized() {
        assert_eq!(
            LinuxLayout::Ilp32.interface(),
            InterfaceLayout {
                name_offset: 0,
                function_list_offset: 4,
                flags_offset: 8,
                stride: 12
            }
        );
        assert_eq!(
            LinuxLayout::Lp64.interface(),
            InterfaceLayout {
                name_offset: 0,
                function_list_offset: 8,
                flags_offset: 16,
                stride: 24
            }
        );
    }

    #[test]
    fn version_and_provenance_boundaries_match_policy() {
        assert_eq!(
            select(Provenance::LegacyFunctionList, Version { major: 2, minor: 0 }),
            Selection::Exact(67)
        );
        assert_eq!(
            select(Provenance::LegacyFunctionList, Version { major: 2, minor: 40 }),
            Selection::Exact(68)
        );
        assert_eq!(
            select(Provenance::LegacyFunctionList, Version { major: 3, minor: 2 }),
            Selection::KnownPrefix(68)
        );
        assert_eq!(
            select(Provenance::StandardInterface, Version { major: 2, minor: 30 }),
            Selection::Refuse
        );
        assert_eq!(
            select(Provenance::StandardInterface, Version { major: 3, minor: 1 }),
            Selection::Exact(92)
        );
        assert_eq!(
            select(Provenance::StandardInterface, Version { major: 3, minor: 2 }),
            Selection::Exact(104)
        );
        assert_eq!(
            select(Provenance::StandardInterface, Version { major: 3, minor: 3 }),
            Selection::KnownPrefix(104)
        );
        assert_eq!(
            select(Provenance::StandardInterface, Version { major: 4, minor: 0 }),
            Selection::Refuse
        );
    }
}
