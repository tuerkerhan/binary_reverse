# gen_cfg_dict.py
#!/usr/bin/env python3
import angr
import pprint
import sys

def generate_cfg_dict(binary_path):
    proj = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGFast()
    functions = {}
    for fn_addr, fn in cfg.kb.functions.items():
        fn_key = (hex(fn_addr), fn.name)
        blocks = {}
        for block in fn.blocks:
            insts = [(insn.mnemonic, insn.op_str) for insn in block.capstone.insns]
            blocks[hex(block.addr)] = insts
        functions[fn_key] = blocks
    return functions

if __name__ == '__main__':
    # if you give one arg, use it; if none, default to ./fauxware
    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [path_to_fauxware]")
        sys.exit(1)
    binary = sys.argv[1] if len(sys.argv) == 2 else "./fauxware"
    print(f"[+] Loading binary: {binary}")
    cfg_dict = generate_cfg_dict(binary)
    pprint.pprint(cfg_dict)
