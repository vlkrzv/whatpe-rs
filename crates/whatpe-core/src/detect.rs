use goblin::pe::PE;
use goblin::pe::characteristic::is_dll;
use goblin::pe::clr::{
    COMIMAGE_FLAGS_32BITPREFERRED, COMIMAGE_FLAGS_32BITREQUIRED, COMIMAGE_FLAGS_ILONLY,
};
use goblin::pe::dll_characteristic::{
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
};
use goblin::pe::header::{
    COFF_MACHINE_ARM, COFF_MACHINE_ARM64, COFF_MACHINE_ARMNT, COFF_MACHINE_IA64, COFF_MACHINE_X86,
    COFF_MACHINE_X86_64,
};
use goblin::pe::optional_header::OptionalHeader;
use goblin::pe::subsystem::{
    IMAGE_SUBSYSTEM_EFI_APPLICATION, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
    IMAGE_SUBSYSTEM_EFI_ROM, IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, IMAGE_SUBSYSTEM_NATIVE,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS, IMAGE_SUBSYSTEM_OS2_CUI, IMAGE_SUBSYSTEM_POSIX_CUI,
    IMAGE_SUBSYSTEM_UNKNOWN, IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_SUBSYSTEM_WINDOWS_GUI,
    IMAGE_SUBSYSTEM_XBOX,
};

use crate::{Category, Item};

/// Not defined in `goblin::pe::subsystem`.
const IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG: u16 = 17;

/// Deterministic builds (`/deterministic`, the .NET SDK's Roslyn default) replace the PE
/// TimeDateStamp with a hash of the file's own content, and the linker-version fields aren't
/// meaningful either since Roslyn writes the PE directly rather than going through link.exe.
/// Such builds add an `IMAGE_DEBUG_TYPE_REPRO` entry to the debug directory to say so -- goblin
/// surfaces that directly as `DebugData::repro_info`.
fn is_deterministic_build(pe: &PE) -> bool {
    pe.debug_data
        .as_ref()
        .is_some_and(|debug_data| debug_data.repro_info.is_some())
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        IMAGE_SUBSYSTEM_NATIVE => "Native",
        IMAGE_SUBSYSTEM_WINDOWS_GUI => "Windows GUI",
        IMAGE_SUBSYSTEM_WINDOWS_CUI => "Windows Console",
        IMAGE_SUBSYSTEM_OS2_CUI => "OS/2 Console",
        IMAGE_SUBSYSTEM_POSIX_CUI => "POSIX Console",
        IMAGE_SUBSYSTEM_NATIVE_WINDOWS => "Native Win9x driver",
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => "Windows CE GUI",
        IMAGE_SUBSYSTEM_EFI_APPLICATION => "EFI Application",
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => "EFI Boot Service Driver",
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => "EFI Runtime Driver",
        IMAGE_SUBSYSTEM_EFI_ROM => "EFI ROM",
        IMAGE_SUBSYSTEM_XBOX => "XBOX",
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION => "Windows BOOT APPLICATION",
        IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG => "XBOX Code Catalog",
        _ => "Unknown",
    }
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        COFF_MACHINE_X86 => "x86",
        COFF_MACHINE_X86_64 => "x64",
        COFF_MACHINE_IA64 => "IA-64",
        COFF_MACHINE_ARM => "ARM (legacy)",
        COFF_MACHINE_ARMNT => "ARM32",
        COFF_MACHINE_ARM64 => "ARM64",
        _ => "Unknown",
    }
}

fn description(pe: &PE, optional_header: &OptionalHeader) -> String {
    let subsystem = optional_header.windows_fields.subsystem;

    if subsystem == IMAGE_SUBSYSTEM_NATIVE {
        return "Windows kernel component or driver".to_string();
    }

    if subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI || subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI {
        if is_dll(pe.header.coff_header.characteristics) {
            return "Windows Dynamic-Link Library (DLL)".to_string();
        }

        if subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI {
            return "Windows Console Application (EXE)".to_string();
        }

        return "Windows Application (EXE)".to_string();
    }

    if subsystem == IMAGE_SUBSYSTEM_UNKNOWN {
        return "Portable Executable Image".to_string();
    }

    subsystem_name(subsystem).to_string()
}

// http://weblog.ikvm.net/2011/11/14/ManagedPEFileTypes.aspx
fn platform(pe: &PE) -> String {
    let machine = machine_name(pe.header.coff_header.machine);

    if pe.is_64 {
        return format!("64-bit ({machine})");
    }

    if let Some(clr) = &pe.clr_data {
        let flags = clr.cor20_header.flags;
        if flags & COMIMAGE_FLAGS_ILONLY != 0 {
            if flags & COMIMAGE_FLAGS_32BITPREFERRED != 0 {
                return "Any CPU 32-bit preferred".to_string();
            }

            if flags & COMIMAGE_FLAGS_32BITREQUIRED == 0 {
                return "Any CPU".to_string();
            }
        }
    }

    format!("32-bit ({machine})")
}

fn build_time(pe: &PE) -> String {
    if is_deterministic_build(pe) {
        return "N/A (deterministic build)".to_string();
    }

    let timestamp = pe.header.coff_header.time_date_stamp as i64;
    match chrono::DateTime::from_timestamp(timestamp, 0) {
        Some(date_time) => date_time.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "INVALID".to_string(),
    }
}

/// Every VS release since VS2015 shares linker major version 14 ("v140" onward) and is only
/// distinguished by the minor version, which keeps climbing across VS updates without the
/// toolset ever being renamed -- e.g. VS2022 alone spans roughly 14.30 through 14.4x. Below
/// VS2015, each VS release had its own distinct linker major version instead, so those are
/// matched exactly rather than by range.
///
/// Minor-version-to-VS-year ranges per:
/// <https://learn.microsoft.com/en-us/cpp/overview/compiler-versions>
/// <https://devblogs.microsoft.com/cppblog/msvc-toolset-minor-version-number-14-40-in-vs-2022-v17-10/>
///
/// The Rich header check corroborates the linker-version fields: several non-MSVC linkers
/// (notably lld-link, used to build Electron/Chromium apps) mimic MSVC's version-field
/// conventions -- typically reporting a fixed 14.0 -- without ever emitting a Rich header, which
/// is why an Electron app can misleadingly read as "Visual Studio 2015". goblin parses the Rich
/// header as part of `PE::parse` already, so presence is just `pe.header.rich_header.is_some()`.
fn toolset(pe: &PE, optional_header: &OptionalHeader) -> Item {
    if is_deterministic_build(pe) {
        return Item::new("Toolset", "N/A (deterministic build)");
    }

    let major = optional_header.standard_fields.major_linker_version;
    let minor = optional_header.standard_fields.minor_linker_version;
    let linker_version = ((major as u16) << 8) | minor as u16;

    let toolset_name = if major == 14 {
        match minor {
            0 => "Visual Studio 2015",
            1..=19 => "Visual Studio 2017",
            20..=29 => "Visual Studio 2019",
            30..=49 => "Visual Studio 2022",
            _ => "Visual Studio 2026 or later",
        }
    } else {
        match linker_version {
            0x0c00 => "Visual Studio 2013",
            0x0b00 => "Visual Studio 2012",
            0x0a00 => "Visual Studio 2010",
            0x0900 => "Visual Studio 2008",
            0x0800 => "Visual Studio 2005",
            0x070a => "Visual Studio .NET 2003",
            0x0700 => "Visual Studio .NET 2002",
            0x0600 => "Visual Studio 6.0",
            0x0500 => "Visual Studio 5.0",
            0x3000 => "Visual Studio C#",
            _ => "(Unknown)",
        }
    };

    let value = format!("v{major}.{minor} ({toolset_name})");

    if pe.header.rich_header.is_none() {
        Item::with_note(
            "Toolset",
            value,
            "No Rich header found -- likely non-Microsoft linker",
        )
    } else {
        Item::new("Toolset", value)
    }
}

/// Debug/Release detection isn't implemented yet: for native binaries it requires parsing the
/// `VERSIONINFO` resource (`VS_FIXEDFILEINFO.dwFileFlags & VS_FF_DEBUG`), and for .NET
/// assemblies it requires reading the `DebuggableAttribute` custom attribute out of the ECMA-335
/// metadata tables. Both are real chunks of work, deliberately deferred to a follow-up rather
/// than silently dropped -- surfaced here as an explicit placeholder so callers see it's known
/// to be missing, not broken.
fn configuration() -> Item {
    Item::with_note(
        "Configuration",
        "(not yet implemented)",
        "Native Debug/Release needs VERSIONINFO resource parsing; .NET needs custom-attribute \
         metadata parsing -- both deferred to a follow-up",
    )
}

pub(crate) fn build_category(pe: &PE, optional_header: &OptionalHeader) -> Category {
    Category {
        name: "Build".to_string(),
        items: vec![
            Item::new("Description", description(pe, optional_header)),
            Item::new("Build time", build_time(pe)),
            configuration(),
            Item::new("Platform", platform(pe)),
            toolset(pe, optional_header),
        ],
    }
}

/// Target Framework and Assembly Version both live in ECMA-335 custom attributes
/// (`TargetFrameworkAttribute`, the assembly's `AssemblyVersionAttribute`/manifest version),
/// which requires walking the `#~` metadata stream's tables -- not yet ported. Emitted as an
/// explicit placeholder, same reasoning as `configuration()` above.
pub(crate) fn dotnet_category() -> Category {
    let reason = "Requires ECMA-335 custom-attribute metadata parsing -- deferred to a follow-up";
    Category {
        name: ".NET".to_string(),
        items: vec![
            Item::with_note("Target Framework", "(not yet implemented)", reason),
            Item::with_note("Assembly Version", "(not yet implemented)", reason),
        ],
    }
}

pub(crate) fn security_category(optional_header: &OptionalHeader) -> Category {
    let dll_characteristics = optional_header.windows_fields.dll_characteristics;

    let dep = if dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
        "Yes"
    } else {
        "No"
    };

    let aslr = if dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
        "No"
    } else if dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
        "Yes (High Entropy)"
    } else {
        "Yes"
    };

    let cfg = if dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
        "Yes"
    } else {
        "No"
    };

    Category {
        name: "Security".to_string(),
        items: vec![
            Item::new("DEP", dep),
            Item::new("ASLR", aslr),
            Item::new("CFG", cfg),
        ],
    }
}
