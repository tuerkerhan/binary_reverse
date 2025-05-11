import angr
p = angr.Project("fauxware", auto_load_libs=False)
print(p.arch.name)  # örn: AMD64




cfg = p.analyses.CFGFast()
for addr, func in cfg.kb.functions.items():
    print(hex(addr), func.name)
    for block in func.blocks:
        print(f"  Block @ {hex(block.addr)}")
        for insn in block.capstone.insns:
            print(f"    {insn.mnemonic} {insn.op_str}")