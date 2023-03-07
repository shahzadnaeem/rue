use std::{
    collections::HashMap, ffi::c_void, mem, os::unix::process::CommandExt, process::Command, str,
};

use nix::{
    sys::{
        ptrace::{self},
        wait::waitpid,
    },
    unistd::Pid,
};
use owo_colors::OwoColorize;
use serde_json::Value;

#[derive(PartialEq, Clone, Copy)]
pub enum PathArg {
    Rdi,
    Rsi,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let syscall_table = build_syscall_table();

    let mut command = Command::new("cat");
    command.arg("./small.hosts");
    unsafe {
        command.pre_exec(|| {
            use nix::sys::ptrace::traceme;
            traceme().map_err(|e| e.into())
        });
    }

    let child = command.spawn()?;
    let child_pid = Pid::from_raw(child.id() as _);
    let res = waitpid(child_pid, None)?;
    eprintln!("first wait: {:?}", res.yellow());

    let mut is_sys_exit = false;
    loop {
        ptrace::syscall(child_pid, None)?;
        _ = waitpid(child_pid, None)?;
        if is_sys_exit {
            let regs = ptrace::getregs(child_pid)?;

            let file_arg_no = syscall_table[&regs.orig_rax].1;

            let path = if file_arg_no == Some(PathArg::Rdi) {
                get_string_from_addr(child_pid, regs.rdi)
            } else if file_arg_no == Some(PathArg::Rsi) {
                get_string_from_addr(child_pid, regs.rsi)
            } else {
                format!("")
            };

            eprintln!(
                "{}({:x}, {:x}{}, {:x}, ...) = {:x}",
                syscall_table[&regs.orig_rax].0.green(),
                regs.rdi.blue(),
                regs.rsi.blue(),
                path.green(),
                regs.rdx.blue(),
                regs.rax.yellow(),
            );
        }
        is_sys_exit = !is_sys_exit;
    }
}

pub fn build_syscall_table() -> HashMap<u64, (String, Option<PathArg>)> {
    const RDI_IDX: usize = 3;
    const RSI_IDX: usize = 4;

    let json: Value = serde_json::from_str(include_str!("syscall.json")).unwrap();

    let syscall_table: HashMap<u64, (String, Option<PathArg>)> = json["aaData"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let mut idx: Option<PathArg> = None;

            let filename_arg_idx = if let Value::Array(ary) = item {
                if let Some(Value::String(v)) = ary[RDI_IDX].get("type") {
                    if v.contains("const char __user * filename") {
                        idx = Some(PathArg::Rdi);
                    } else if let Some(Value::String(v)) = ary[RSI_IDX].get("type") {
                        if v.contains("const char __user * filename") {
                            idx = Some(PathArg::Rsi);
                        }
                    }
                }

                idx
            } else {
                idx
            };

            (
                item[0].as_u64().unwrap(),
                (item[1].as_str().unwrap().to_owned(), filename_arg_idx),
            )
        })
        .collect();

    syscall_table
}

pub fn get_string_from_addr(pid: Pid, addr: u64) -> String {
    let mut full_path = String::new();
    let mut addr = addr;

    loop {
        let w1 = ptrace::read(pid, addr as *mut c_void);

        if let Ok(pp) = w1 {
            let bytes = pp
                .to_le_bytes()
                .into_iter()
                .take_while(|b| *b != 0u8)
                .collect::<Vec<_>>();

            full_path.push_str(str::from_utf8(&bytes).unwrap());

            addr += mem::size_of::<u64>() as u64;

            if bytes.len() < mem::size_of::<u64>() {
                break;
            }
        } else {
            full_path = format!("FILE_PATH - Error :( {:x}", addr);
            break;
        }
    }

    format!(" \"{}\"", full_path)
}
