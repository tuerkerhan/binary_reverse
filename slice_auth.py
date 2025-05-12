# slice_auth.py
#!/usr/bin/env python3
import angr
import sys

def backward_slice_authenticate(binary_path):
    proj = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFGEmulated(
        keep_state=True,
        state_add_options=angr.sim_options.refs,
        context_sensitivity_level=2
    )
    cdg = proj.analyses.CDG(cfg)
    ddg = proj.analyses.DDG(cfg)

    try:
        auth_func = cfg.kb.functions.function(name='authenticate')
    except KeyError:
        raise RuntimeError("Function 'authenticate' not found in CFG.")

    # pick any node at its entry
    target_node = cfg.model.get_any_node(auth_func.addr)
    bs = proj.analyses.BackwardSlice(
        cfg,
        cdg=cdg,
        ddg=ddg,
        targets=[ (target_node, -1) ]
    )

    print("Data‐flow backward slice of 'authenticate':")
    for bb_addr, stmt_ids in bs.chosen_statements.items():
        print(f"  0x{bb_addr:x}: statements {stmt_ids}")

if __name__ == '__main__':
    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [path_to_fauxware]")
        sys.exit(1)
    binary = sys.argv[1] if len(sys.argv) == 2 else "./fauxware"
    print(f"[+] Loading binary: {binary}")
    backward_slice_authenticate(binary)
